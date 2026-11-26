package com.aegis.kid.security

import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64

/**
 * The device-side half of "No Local Override".
 *
 * When a blocked resource is genuinely needed (e.g. an unindexed
 * NCERT article), the device does NOT decide locally and does NOT
 * accept a parent PIN. It submits this challenge to the Cloud AI
 * Safety Adjudicator, which may return a [PolicyToken].
 *
 * Prompt-injection defence — by construction, not by filtering:
 *  - The challenge contains ONLY: a pseudonymous device ID, ONE
 *    resource (URL or package ID), the age tier, a nonce, and a
 *    timestamp. There is NO free-text field, NO reason field, NO
 *    user message, NO browsing history, and NO child PII.
 *  - There is therefore nothing for a child (or a malicious page)
 *    to inject a persuasive essay into. If a field is added here
 *    in future, it must be an enumerated/validated value, never
 *    free text, and the backend must treat it as untrusted data.
 *  - The resource is normalised before signing: URLs are reduced
 *    to scheme + host + path (query string and fragment stripped,
 *    so data cannot be exfiltrated in a query), package IDs must
 *    match the Android package pattern.
 *
 * WIRE CONTRACT — what is signed vs what is sent (Deliverable 5,
 * `backend/app/crypto.py::unblock_payload` + `models.UnblockRequest`):
 *  - SIGNED bytes (what the device Keystore key signs): the backend
 *    canonical JSON `{"age_tier":"AGE_5_8","nonce":"...","resource":"..."}`
 *    (keys sorted, no spaces). `device_id` and `timestamp` are
 *    TRANSPORT fields only — they are NOT part of the signed bytes.
 *    (A backend docstring says "resource|age_tier|nonce"; that is
 *    stale — the code signs the canonical JSON above, and the code
 *    governs. See SECURITY.md §6.)
 *  - SENT wire JSON (`toJson()`): exactly the backend `UnblockRequest`
 *    fields — `device_id`, `resource_url_or_package`, `age_tier`,
 *    `nonce`, `device_signature`. The backend model has
 *    `extra="forbid"`, so NO extra field (including `timestamp`)
 *    may be sent. Freshness is enforced server-side by the nonce
 *    TTL (15 minutes), not by a device timestamp.
 *  - `resource` is capped at 512 chars (backend `max_length=512`).
 */
data class UnblockChallenge(
    /** Pseudonymous device UUID generated at provisioning. NOT IMEI / serial / child name. */
    val deviceId: String,
    /** Single normalised resource: https URL (no query/fragment) or package ID. */
    val resource: String,
    val ageTier: AgeTier,
    val nonce: String,
    /** Local creation time (epoch seconds). Transport-only: never sent, never signed. */
    val timestampEpochSeconds: Long,
    /** Base64 signature over [signedPayload] by the device Keystore key. Null if signing failed. */
    val signatureBase64: String?,
) {
    /**
     * The exact bytes that are signed — backend canonical JSON.
     * Must byte-match `unblock_payload(resource, ageTier, nonce)`
     * on the backend, or the backend rejects the challenge (401).
     */
    fun signedPayload(): String =
        """{"age_tier":${JSONObject.quote(ageTier.name)},"nonce":${JSONObject.quote(nonce)},"resource":${JSONObject.quote(resource)}}"""

    /** Wire JSON for POST /api/v1/unblock/request — exactly the backend model's fields, nothing more. */
    fun toJson(): JSONObject = JSONObject().apply {
        put("device_id", deviceId)
        put("resource_url_or_package", resource)
        put("age_tier", ageTier.name)
        put("nonce", nonce)
        put("device_signature", signatureBase64)
    }

    override fun toString(): String =
        "UnblockChallenge(deviceId=${HardwareKeystoreManager.truncated(deviceId)}, " +
            "resource=$resource, ageTier=${ageTier.name}, " +
            "nonce=${HardwareKeystoreManager.truncated(nonce)}, timestamp=$timestampEpochSeconds)"

    companion object {
        private val PACKAGE_ID_REGEX = Regex("^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$")
        /** Backend UnblockRequest max_length=512. */
        private const val MAX_RESOURCE_LENGTH = 512

        fun generateNonce(): String {
            val bytes = ByteArray(16)
            SecureRandom().nextBytes(bytes)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }

        /**
         * Normalise a requested resource. Returns null if it cannot
         * be a legitimate single resource — the caller must then
         * refuse the challenge instead of sending a malformed one.
         *  - https:// URLs: lower-cased host, query + fragment stripped.
         *  - Package IDs: must match [PACKAGE_ID_REGEX].
         *  - Anything else (http, javascript:, data:, free text with
         *    spaces, over-long input) is rejected.
         */
        fun normaliseResource(raw: String): String? {
            val trimmed = raw.trim()
            if (trimmed.isEmpty() || trimmed.length > MAX_RESOURCE_LENGTH) return null
            if (trimmed.contains(' ') || trimmed.contains('\n') || trimmed.contains('\r')) return null
            if (trimmed.startsWith("https://", ignoreCase = true)) {
                return try {
                    val uri = java.net.URI(trimmed)
                    val host = uri.host?.lowercase() ?: return null
                    if (host.isBlank()) return null
                    val path = uri.rawPath?.takeIf { it.isNotBlank() } ?: ""
                    "https://$host$path"
                } catch (_: Exception) {
                    null
                }
            }
            if (PACKAGE_ID_REGEX.matches(trimmed)) return trimmed
            return null
        }

        /**
         * Build and sign a challenge. Returns null if the resource
         * is invalid or signing fails — both fail closed (no
         * unsigned challenge is ever sent).
         */
        fun build(
            deviceId: String,
            rawResource: String,
            ageTier: AgeTier,
            signer: Ed25519Signer,
            timestampEpochSeconds: Long = System.currentTimeMillis() / 1000L,
        ): UnblockChallenge? {
            if (deviceId.isBlank()) return null
            val resource = normaliseResource(rawResource) ?: return null
            val unsigned = UnblockChallenge(
                deviceId = deviceId,
                resource = resource,
                ageTier = ageTier,
                nonce = generateNonce(),
                timestampEpochSeconds = timestampEpochSeconds,
                signatureBase64 = null,
            )
            val signature = signer.signUtf8(unsigned.signedPayload()) ?: return null
            return unsigned.copy(signatureBase64 = signature)
        }
    }
}
