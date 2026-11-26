package com.aegis.kid.security

import org.json.JSONObject
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * A time-bound, single-resource unblock token issued by the Cloud AI
 * Safety Adjudicator (auto-issue, 24 h) or the Human Support Team.
 *
 * The token carries NO child PII: no name, no browsing history, no
 * free text, no reason field. Only the resource, the age tier, an
 * expiry, and a nonce — exactly what was in the signed challenge.
 *
 * WIRE CONTRACT — canonical payload (what the backend signs, and
 * what [Ed25519Verifier] re-computes offline). This MUST match the
 * backend exactly (Deliverable 5, `backend/app/crypto.py`):
 * `canonical_json` = JSON, keys sorted, no spaces
 * (`json.dumps(payload, sort_keys=True, separators=(",", ":"))`):
 *
 *   {"age_tier":"AGE_5_8","expires_at":"2026-11-26T10:00:00+00:00","nonce":"...","resource":"..."}
 *
 * Field notes:
 *  - `age_tier` is the backend enum value, i.e. the enum NAME
 *    ("AGE_5_8"), not the display code ("5-8").
 *  - `expires_at` is an ISO-8601 string, kept VERBATIM as received.
 *    Do NOT re-derive it from epoch seconds: Python's `isoformat()`
 *    may carry microseconds, and any re-formatting changes the
 *    signed bytes and breaks verification. [expiresAtIso] is the
 *    signed value; [expiresAtEpochSeconds] is derived from it for
 *    expiry checks only and is never used in the canonical payload.
 *  - `issued_at` (present in the backend model) is NOT part of the
 *    signed payload and is ignored on parse.
 */
enum class AgeTier(val code: String) {
    AGE_5_8("5-8"),
    AGE_9_12("9-12"),
    AGE_13_15("13-15"),
    AGE_16_17("16-17");

    companion object {
        fun fromCode(code: String): AgeTier? = entries.firstOrNull { it.code == code }
        fun fromName(name: String): AgeTier? =
            entries.firstOrNull { it.name == name }
    }
}

data class PolicyToken(
    /** Single resource: an https URL (host + path, no query) or an app package ID. */
    val resource: String,
    val ageTier: AgeTier,
    /**
     * Expiry as an ISO-8601 string, VERBATIM as issued by the backend
     * (e.g. "2026-11-26T10:00:00+00:00"). Auto-issued tokens: 24 h from issue.
     */
    val expiresAtIso: String,
    /** Single-use replay-protection nonce (Base64URL, >= 16 bytes of entropy). */
    val nonce: String,
    /** Ed25519 signature (Base64) over [canonicalPayload] by the backend key. */
    val signatureBase64: String,
) {
    sealed class ValidationResult {
        data object Valid : ValidationResult()
        data class Invalid(val reason: String) : ValidationResult()
    }

    /** Expiry as epoch seconds, parsed from [expiresAtIso]. Long.MIN_VALUE if unparseable (fail closed). */
    val expiresAtEpochSeconds: Long
        get() = parseIsoToEpoch(expiresAtIso) ?: Long.MIN_VALUE

    /**
     * Backend canonical JSON for signing. Keys sorted alphabetically,
     * no whitespace, strings JSON-escaped via [JSONObject.quote].
     * Must byte-match `canonical_json(token_payload(...))` on the backend.
     */
    fun canonicalPayload(): String =
        """{"age_tier":${JSONObject.quote(ageTier.name)},"expires_at":${JSONObject.quote(expiresAtIso)},"nonce":${JSONObject.quote(nonce)},"resource":${JSONObject.quote(resource)}}"""

    fun isExpired(nowEpochSeconds: Long = System.currentTimeMillis() / 1000L): Boolean =
        nowEpochSeconds > expiresAtEpochSeconds + Ed25519Verifier.CLOCK_SKEW_TOLERANCE_SECONDS

    /**
     * Structural validation only — expiry, single-resource binding,
     * age-tier binding, and replay. Signature verification is NOT
     * done here; use [Ed25519Verifier.verifyToken] for the full check.
     */
    fun validate(
        expectedResource: String,
        expectedAgeTier: AgeTier,
        seenNonces: Set<String>,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L,
    ): ValidationResult {
        if (resource.isBlank() || signatureBase64.isBlank() || nonce.isBlank()) {
            return ValidationResult.Invalid("token has blank resource, nonce, or signature")
        }
        if (expiresAtEpochSeconds == Long.MIN_VALUE) {
            return ValidationResult.Invalid("token expires_at is not a parseable ISO-8601 timestamp")
        }
        // Single-resource binding: exact match only. No wildcards,
        // no prefix / host-only matching — a token for one article
        // must not unlock a whole domain.
        if (resource != expectedResource) {
            return ValidationResult.Invalid("token resource does not match requested resource")
        }
        if (ageTier != expectedAgeTier) {
            return ValidationResult.Invalid("token age tier does not match active age tier")
        }
        if (nonce in seenNonces) {
            return ValidationResult.Invalid("nonce already consumed (replay)")
        }
        if (isExpired(nowEpochSeconds)) {
            return ValidationResult.Invalid("token expired")
        }
        // Sanity bound: a token must not live absurdly long even if
        // signed. Auto-issue is 24h; support-issued tokens are
        // capped at 7 days by policy. Anything longer is rejected.
        val maxLifetimeSeconds = 7L * 24L * 3600L
        if (expiresAtEpochSeconds - nowEpochSeconds > maxLifetimeSeconds) {
            return ValidationResult.Invalid("token lifetime exceeds policy maximum (7 days)")
        }
        return ValidationResult.Valid
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("resource", resource)
        put("age_tier", ageTier.name)
        put("expires_at", expiresAtIso)
        put("nonce", nonce)
        put("signature", signatureBase64)
    }

    override fun toString(): String =
        // Never include the signature in toString()/logs.
        "PolicyToken(resource=$resource, ageTier=${ageTier.name}, " +
            "expiresAt=$expiresAtIso, nonce=${HardwareKeystoreManager.truncated(nonce)})"

    companion object {
        /** Parse an ISO-8601 timestamp (with offset, e.g. "+00:00") to epoch seconds. Null if unparseable. */
        fun parseIsoToEpoch(iso: String): Long? = try {
            OffsetDateTime.parse(iso, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toEpochSecond()
        } catch (_: Exception) {
            try {
                Instant.parse(iso).epochSecond
            } catch (_: Exception) {
                null
            }
        }

        /** Format epoch seconds as ISO-8601 UTC ("...+00:00"), matching Python `datetime.isoformat()` without microseconds. */
        fun epochToIso(epochSeconds: Long): String =
            OffsetDateTime.ofInstant(Instant.ofEpochSecond(epochSeconds), ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)

        /**
         * Parse a token from the backend's JSON. Returns null on any
         * malformed / missing field — malformed tokens fail closed.
         * `expires_at` is expected as an ISO-8601 string (backend
         * format); a numeric epoch value is also accepted and
         * converted, for robustness. Unknown extra fields (e.g.
         * `issued_at`) are ignored (forward compatibility).
         */
        fun parse(json: String): PolicyToken? = try {
            val obj = JSONObject(json)
            val ageTier = AgeTier.fromName(obj.optString("age_tier"))
                ?: AgeTier.fromCode(obj.optString("age_tier"))
                ?: return null
            val expiresRaw = obj.opt("expires_at") ?: return null
            val expiresAtIso = when (expiresRaw) {
                is Number -> epochToIso(expiresRaw.toLong())
                is String -> expiresRaw
                else -> return null
            }
            PolicyToken(
                resource = obj.getString("resource"),
                ageTier = ageTier,
                expiresAtIso = expiresAtIso,
                nonce = obj.getString("nonce"),
                signatureBase64 = obj.getString("signature"),
            )
        } catch (_: Exception) {
            null
        }

        fun parse(obj: JSONObject): PolicyToken? = parse(obj.toString())
    }
}
