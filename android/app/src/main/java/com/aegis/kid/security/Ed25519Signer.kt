package com.aegis.kid.security

import android.util.Log
import java.security.Signature
import java.util.Base64

/**
 * Signs device-originated payloads with the non-exportable Keystore
 * private key ([HardwareKeystoreManager.KEY_ALIAS]).
 *
 * What this signs — and ONLY this:
 *  - Dead-man heartbeats (see [HeartbeatSigner])
 *  - Unblock challenges (see [UnblockChallenge])
 *
 * It must NEVER sign arbitrary caller-supplied text, URLs from a
 * WebView, or any free-text field. That restriction is the
 * prompt-injection defence: the signer is only reachable through
 * the two typed builders above, whose payloads contain no free text.
 *
 * The signature algorithm is resolved at runtime from the live key
 * ([HardwareKeystoreManager.getAlgorithm]): "Ed25519" on API 33+
 * devices, "SHA256withECDSA" otherwise. Callers and the backend
 * must agree on the algorithm via the device's registered public
 * key, not by assuming one.
 *
 * Output is standard Base64 (no line wraps). No key material and no
 * full signature is ever logged — only a truncated prefix.
 */
class Ed25519Signer(private val keystoreManager: HardwareKeystoreManager) {

    companion object {
        private const val TAG = "AegisSigner"
    }

    /** Algorithm actually in use on this device. */
    fun algorithm(): String = keystoreManager.getAlgorithm()

    /**
     * Sign raw bytes. Returns Base64-encoded signature, or null if
     * the key is absent / the Keystore refuses (e.g. key purged,
     * device locked in a state that blocks Keystore use).
     * A null result is a hard failure: the caller must cache the
     * payload and retry, never send it unsigned.
     */
    fun sign(data: ByteArray): String? {
        val privateKey = keystoreManager.getPrivateKey() ?: run {
            Log.w(TAG, "sign failed: device key absent")
            return null
        }
        return try {
            val signature = Signature.getInstance(algorithm())
            signature.initSign(privateKey)
            signature.update(data)
            val signed = signature.sign()
            val encoded = Base64.getEncoder().encodeToString(signed)
            Log.d(TAG, "signed ${data.size} bytes, sig=${HardwareKeystoreManager.truncated(encoded)}")
            encoded
        } catch (e: Exception) {
            Log.w(TAG, "sign failed: ${e.javaClass.simpleName}")
            null
        }
    }

    /** Convenience overload for canonical (already deterministic) UTF-8 payloads. */
    fun signUtf8(canonicalPayload: String): String? =
        sign(canonicalPayload.toByteArray(Charsets.UTF_8))

    /** Public key (Base64, X.509-encoded) to register with the backend at provisioning. */
    fun publicKeyBase64(): String? = keystoreManager.getPublicKeyBase64()
}
