package com.aegis.kid.security

import android.util.Base64 as AndroidBase64
import android.util.Log
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Verifies tokens issued by the Cloud AI Safety Adjudicator /
 * Human Support Team, OFFLINE, with no network access.
 *
 * Trust root: the backend's Ed25519 public key, pinned in code.
 * It is a PLACEHOLDER below and MUST be replaced with the real
 * production key at provisioning time (injected by the provisioning
 * flow, never committed as a real secret and never fetched over
 * an unauthenticated channel). If the placeholder is still present,
 * every verification fails closed — see [isPlaceholderKey].
 *
 * Verification contract for a [PolicyToken]:
 *  1. Signature verifies over the token's canonical payload
 *     (see [PolicyToken.canonicalPayload]) with the pinned key.
 *     The canonical payload is the backend's canonical JSON
 *     (`{"age_tier":...,"expires_at":"<ISO>","nonce":...,"resource":...}`,
 *     keys sorted, no spaces) — NOT a pipe-delimited string. See
 *     SECURITY.md §6 for the exact cross-deliverable wire contract.
 *  2. Expiry is enforced with 5 minutes of clock-skew tolerance
 *     (see [PolicyToken.validate]).
 *  3. Single-resource binding: the token is valid ONLY for its
 *     exact `resource` and `ageTier` — no wildcards, no prefixes.
 *  4. Replay protection: the `nonce` must not have been seen
 *     before. The caller supplies the set of already-consumed
 *     nonces (persisted by the caller, e.g. in EncryptedShared-
 *     Preferences); this class never invents a nonce store.
 *
 * Verification never logs the token, the resource, or the full
 * signature — only the outcome and a truncated nonce.
 */
object Ed25519Verifier {

    private const val TAG = "AegisVerifier"

    /**
     * PLACEHOLDER — replace at provisioning with the real backend
     * Ed25519 public key (X.509 / SubjectPublicKeyInfo, Base64).
     * This value is NOT a real key. Do not ship the MVP with it.
     */
    const val PLACEHOLDER_BACKEND_PUBLIC_KEY_BASE64: String =
        "REPLACE_ME_WITH_BACKEND_ED25519_PUBLIC_KEY_BASE64"

    /** 5 minutes, in seconds — clock-skew tolerance for token expiry. */
    const val CLOCK_SKEW_TOLERANCE_SECONDS: Long = 300L

    fun isPlaceholderKey(publicKeyBase64: String = PLACEHOLDER_BACKEND_PUBLIC_KEY_BASE64): Boolean =
        publicKeyBase64.isBlank() || publicKeyBase64.startsWith("REPLACE_ME")

    /**
     * Load the pinned backend public key. Tries Ed25519 first
     * (API 33+ KeyFactory), then EC P-256 for backends that issue
     * ECDSA tokens. Returns null (fail closed) on any parse error.
     */
    fun loadBackendPublicKey(publicKeyBase64: String = PLACEHOLDER_BACKEND_PUBLIC_KEY_BASE64): PublicKey? {
        if (isPlaceholderKey(publicKeyBase64)) {
            Log.w(TAG, "Backend public key is still the placeholder — verification fails closed")
            return null
        }
        val decoded = runCatching {
            AndroidBase64.decode(publicKeyBase64, AndroidBase64.NO_WRAP)
        }.getOrNull() ?: run {
            Log.w(TAG, "Backend public key is not valid Base64")
            return null
        }
        val spec = X509EncodedKeySpec(decoded)
        for (algorithm in listOf("Ed25519", "EC")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePublic(spec)
            } catch (_: Exception) {
                // Try the next algorithm; a key is only one of them.
            }
        }
        Log.w(TAG, "Backend public key could not be parsed as Ed25519 or EC")
        return null
    }

    private fun signatureAlgorithmFor(publicKey: PublicKey): String =
        if (publicKey.algorithm.equals("Ed25519", ignoreCase = true)) "Ed25519" else "SHA256withECDSA"

    /**
     * Low-level verify: [signatureBase64] over [canonicalPayload].
     * Returns false on any error, malformed input, or mismatch.
     * This is the only place a raw signature is checked; token-level
     * checks (expiry, binding, replay) live in [PolicyToken.validate].
     */
    fun verifySignedPayload(
        canonicalPayload: String,
        signatureBase64: String,
        publicKey: PublicKey? = loadBackendPublicKey(),
    ): Boolean {
        val key = publicKey ?: return false
        if (signatureBase64.isBlank()) return false
        val signatureBytes = runCatching {
            AndroidBase64.decode(signatureBase64, AndroidBase64.NO_WRAP)
        }.getOrNull() ?: return false
        return try {
            val verifier = Signature.getInstance(signatureAlgorithmFor(key))
            verifier.initVerify(key)
            verifier.update(canonicalPayload.toByteArray(Charsets.UTF_8))
            verifier.verify(signatureBytes)
        } catch (e: Exception) {
            Log.w(TAG, "verify failed: ${e.javaClass.simpleName}")
            false
        }
    }

    /**
     * Full offline token verification. Returns the [PolicyToken]
     * validation result; a token is usable ONLY when the result is
     * [PolicyToken.ValidationResult.Valid] AND the signature checks
     * out. Both gates must pass — structural validity without a
     * valid signature is a forgery, and vice versa.
     *
     * @param seenNonces nonces already consumed on this device.
     *        The caller must add the nonce to that store on success.
     */
    fun verifyToken(
        token: PolicyToken,
        expectedResource: String,
        expectedAgeTier: AgeTier,
        seenNonces: Set<String>,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L,
        publicKey: PublicKey? = loadBackendPublicKey(),
    ): PolicyToken.ValidationResult {
        val structural = token.validate(expectedResource, expectedAgeTier, seenNonces, nowEpochSeconds)
        if (structural !is PolicyToken.ValidationResult.Valid) return structural
        val signatureOk = verifySignedPayload(token.canonicalPayload(), token.signatureBase64, publicKey)
        return if (signatureOk) {
            Log.i(TAG, "Token verified for nonce=${HardwareKeystoreManager.truncated(token.nonce)}")
            PolicyToken.ValidationResult.Valid
        } else {
            Log.w(TAG, "Token signature INVALID for nonce=${HardwareKeystoreManager.truncated(token.nonce)}")
            PolicyToken.ValidationResult.Invalid("signature verification failed")
        }
    }
}
