package com.aegis.kid.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Deliverable 4 — Aegis-Kid OS (India Edition) MVP.
 *
 * Owns the single device identity key for the whole OS.
 *
 * Design contract (DPDP / privacy-by-design):
 *  - One non-exportable signing key, alias [KEY_ALIAS], generated inside
 *    AndroidKeyStore. The private key material NEVER leaves the
 *    TEE / StrongBox. There is no export API, no backup, no key file.
 *  - No child PII is involved in key generation. The attestation
 *    challenge is an opaque server nonce supplied at provisioning.
 *  - No key, signature, or certificate value is ever logged in full.
 *    Only truncated fingerprints (first 8 chars) are logged.
 *
 * Algorithm policy:
 *  - Preferred: Ed25519 (AndroidKeyStore supports it from API 33).
 *    Ed25519 keys have no digest parameter; the Signature instance
 *    is simply "Ed25519".
 *  - Fallback: EC P-256 with SHA256withECDSA (API 23+). This is the
 *    only supported fallback — the rest of the security package
 *    ([Ed25519Signer] / [Ed25519Verifier]) resolves the live
 *    algorithm from [getAlgorithm] and never hard-codes one.
 *  - Callers must NOT assume Ed25519. Always read [getAlgorithm].
 *
 * StrongBox policy:
 *  - StrongBox is requested first ([KeyProperties] via
 *    `setIsStrongBoxBacked(true)`), but it is *guarded*: if the
 *    device has no StrongBox, [StrongBoxUnavailableException] is
 *    caught and generation retries in the TEE. A failed StrongBox
 *    attempt must never brick provisioning on a budget AER tablet.
 *  - `setUserAuthenticationRequired(false)` is deliberate: the
 *    heartbeat watchdog runs in the background (WorkManager /
 *    ForegroundService) with no child or parent present to
 *    authenticate. Requiring biometric/PIN auth would silently
 *    kill the dead-man heartbeat. The key is protected instead by
 *    (a) being non-exportable, (b) living in TEE/StrongBox, and
 *    (c) only being usable by this app's UID under Device Owner.
 *    It must NOT be used to sign anything other than heartbeats
 *    and unblock challenges (see [Ed25519Signer]).
 */
class HardwareKeystoreManager(private val context: Context) {

    companion object {
        const val KEY_ALIAS = "aegis_device_key"
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val TAG = "AegisKeystore"

        /** Truncate fingerprints / signatures before logging. Never log a full value. */
        internal fun truncated(value: String): String =
            if (value.length <= 8) value else value.take(8) + "…"
    }

    enum class KeyOrigin { STRONGBOX, TEE, SOFTWARE, NONE }

    data class KeyInfoResult(
        val exists: Boolean,
        val algorithm: String?,
        val origin: KeyOrigin,
        /** SHA-256 fingerprint of the public key, Base64 — safe to log truncated only. */
        val publicKeyFingerprintBase64: String?,
    )

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    /** True only if the device advertises a StrongBox Keymaster. */
    fun isStrongBoxAvailable(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    fun keyExists(): Boolean = try {
        loadKeyStore().containsAlias(KEY_ALIAS)
    } catch (e: Exception) {
        Log.w(TAG, "keyExists check failed: ${e.javaClass.simpleName}")
        false
    }

    /**
     * Generate the device key if absent, otherwise return the existing
     * key's info. Idempotent — safe to call on every provisioning retry.
     *
     * @param attestationChallenge opaque nonce from the backend at
     *        provisioning time. May be null on re-provisioning where
     *        attestation is re-checked separately. It is NOT child PII.
     */
    fun getOrCreateDeviceKey(attestationChallenge: ByteArray? = null): Result<KeyInfoResult> {
        if (keyExists()) return Result.success(describeKey())
        return generateDeviceKey(attestationChallenge)
    }

    fun generateDeviceKey(attestationChallenge: ByteArray? = null): Result<KeyInfoResult> {
        if (keyExists()) return Result.success(describeKey())

        // Preferred path: Ed25519 on API 33+. Fall back to EC P-256 below.
        val preferEd25519 = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        val attempts: List<() -> Unit> = if (preferEd25519) {
            listOf(
                { generateEd25519Key(attestationChallenge, strongBox = true) },
                { generateEd25519Key(attestationChallenge, strongBox = false) },
                { generateEcKey(attestationChallenge, strongBox = false) },
            )
        } else {
            listOf(
                { generateEcKey(attestationChallenge, strongBox = true) },
                { generateEcKey(attestationChallenge, strongBox = false) },
            )
        }

        var lastError: Exception? = null
        for (attempt in attempts) {
            try {
                attempt()
                val info = describeKey()
                Log.i(TAG, "Device key generated: alg=${info.algorithm} origin=${info.origin}")
                return Result.success(info)
            } catch (e: StrongBoxUnavailableException) {
                Log.w(TAG, "StrongBox unavailable, falling back to TEE: ${e.message}")
                lastError = e
            } catch (e: Exception) {
                Log.w(TAG, "Key generation attempt failed: ${e.javaClass.simpleName}")
                lastError = e
                // A half-created alias must not poison the next attempt.
                runCatching { deleteKey() }
            }
        }
        return Result.failure(
            IllegalStateException("Failed to generate device key in Keystore", lastError),
        )
    }

    private fun generateEd25519Key(challenge: ByteArray?, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .apply {
                // Ed25519: no digest is set — the algorithm is the digest.
                // setUserAuthenticationRequired(false) is required for the
                // background heartbeat (see class KDoc).
                setUserAuthenticationRequired(false)
                setIsStrongBoxBacked(strongBox)
                if (challenge != null) setAttestationChallenge(challenge)
                // Ed25519 keys are non-exportable by construction in
                // AndroidKeyStore; there is no export flag to set.
            }
            .build()
        // NOTE: KeyGenParameterSpec.Builder requires an AlgorithmParameterSpec
        // for EC only. For Ed25519 the spec above carries no curve parameter;
        // KeyPairGenerator initialised with "Ed25519" + this spec is the
        // documented API 33+ path. If the platform rejects it, the caller
        // falls through to the EC P-256 path in generateDeviceKey().
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_ED25519, KEYSTORE_PROVIDER)
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    private fun generateEcKey(challenge: ByteArray?, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .apply { if (challenge != null) setAttestationChallenge(challenge) }
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    /** Live signature algorithm for this device: "Ed25519" or "SHA256withECDSA". */
    fun getAlgorithm(): String =
        if (describeKey().algorithm.equals(KeyProperties.KEY_ALGORITHM_ED25519, ignoreCase = true)) {
            "Ed25519"
        } else {
            "SHA256withECDSA"
        }

    fun getPublicKey(): PublicKey? = try {
        loadKeyStore().getCertificate(KEY_ALIAS)?.publicKey
    } catch (e: Exception) {
        Log.w(TAG, "getPublicKey failed: ${e.javaClass.simpleName}")
        null
    }

    fun getPublicKeyBase64(): String? =
        getPublicKey()?.encoded?.let { Base64.getEncoder().encodeToString(it) }

    fun getPrivateKey(): PrivateKey? = try {
        loadKeyStore().getKey(KEY_ALIAS, null) as? PrivateKey
    } catch (e: Exception) {
        Log.w(TAG, "getPrivateKey failed: ${e.javaClass.simpleName}")
        null
    }

    /**
     * Key attestation certificate chain (leaf first). Empty if the key
     * was generated without an attestation challenge or attestation is
     * unavailable on this device. Callers must treat an empty chain as
     * "attestation unavailable", not as "device is tampered".
     */
    fun getAttestationChain(): List<Certificate> = try {
        loadKeyStore().getCertificateChain(KEY_ALIAS)?.toList().orEmpty()
    } catch (e: Exception) {
        Log.w(TAG, "getAttestationChain failed: ${e.javaClass.simpleName}")
        emptyList()
    }

    fun describeKey(): KeyInfoResult {
        val publicKey = getPublicKey()
        if (publicKey == null) {
            return KeyInfoResult(exists = false, algorithm = null, origin = KeyOrigin.NONE, publicKeyFingerprintBase64 = null)
        }
        val origin = resolveOrigin()
        val fingerprint = runCatching {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            Base64.getEncoder().encodeToString(digest.digest(publicKey.encoded))
        }.getOrNull()
        return KeyInfoResult(
            exists = true,
            algorithm = publicKey.algorithm,
            origin = origin,
            publicKeyFingerprintBase64 = fingerprint,
        )
    }

    /**
     * Resolve TEE vs StrongBox vs software from KeyInfo security level
     * (API 31+). Below API 31, or if KeyInfo is unavailable, report TEE
     * — AndroidKeyStore keys are hardware-backed on all AER devices in
     * practice, and StrongBox is separately advertised via
     * [isStrongBoxAvailable]; never claim StrongBox without evidence.
     */
    private fun resolveOrigin(): KeyOrigin {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return KeyOrigin.TEE
        return try {
            val privateKey = getPrivateKey() ?: return KeyOrigin.NONE
            val factory = KeyFactory.getInstance(privateKey.algorithm, KEYSTORE_PROVIDER)
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
            when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyOrigin.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyOrigin.TEE
                else -> KeyOrigin.SOFTWARE
            }
        } catch (e: Exception) {
            Log.w(TAG, "resolveOrigin failed: ${e.javaClass.simpleName}")
            KeyOrigin.TEE
        }
    }

    fun deleteKey(): Boolean = try {
        loadKeyStore().deleteEntry(KEY_ALIAS)
        Log.i(TAG, "Device key deleted: alias=$KEY_ALIAS")
        true
    } catch (e: Exception) {
        Log.w(TAG, "deleteKey failed: ${e.javaClass.simpleName}")
        false
    }

    /**
     * Un-enrollment purge. Called ONLY from the Device Owner
     * unenrollment flow (after DigiLocker parent re-verification and
     * Human Support approval — never from the device alone).
     * Deletes the device key AND the cached heartbeat queue so a
     * re-enrolled device cannot replay old signed heartbeats.
     * The [HeartbeatCache] purge is the caller's responsibility —
     * this method deletes the key; pass a cache instance to also
     * clear it atomically from the same call site.
     */
    fun purgeOnUnenrollment(heartbeatCache: HeartbeatCache? = null): Boolean {
        heartbeatCache?.clear()
        return deleteKey()
    }
}
