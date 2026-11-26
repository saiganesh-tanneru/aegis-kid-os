package com.aegis.kid.security

import android.content.Context
import android.content.SharedPreferences
import android.provider.Settings
import android.util.Log
import java.security.cert.Certificate
import java.security.cert.X509Certificate

/**
 * Hardware attestation + boot-count tamper detection.
 *
 * Two independent signals, neither of which is trusted alone:
 *  1. Keystore key attestation — the certificate chain issued when
 *     the device key was generated with an attestation challenge.
 *     Proves the key lives in hardware (TEE/StrongBox) and was
 *     generated on THIS device. An empty chain means
 *     "attestation unavailable", not "tampered".
 *  2. Boot count — `Settings.Global` BOOT_COUNT, persisted across
 *     runs. An unexpected reset (boot count goes backwards, or
 *     drops to a small value after having been large) is a
 *     tamper signal the backend correlates with missing
 *     heartbeats (see SECURITY.md).
 *
 * Play Integrity / SafetyNet note: SafetyNet is deprecated and
 * must NOT be used. The modern equivalent is the Play Integrity
 * API, which is a *server-side* verdict — it cannot be checked
 * purely on-device. [checkDeviceIntegrity] therefore performs
 * the on-device checks available here and documents that the
 * Play Integrity verdict must be obtained by the backend.
 * Do not present a local-only result as a Play Integrity verdict.
 */
class AttestationChecker(
    private val context: Context,
    private val keystoreManager: HardwareKeystoreManager,
) {
    companion object {
        private const val TAG = "AegisAttestation"
        private const val PREFS_NAME = "aegis_attestation"
        private const val KEY_LAST_BOOT_COUNT = "last_boot_count"
        /** A reset to a value this far below the previous count is treated as a reset, not a wrap. */
        private const val BOOT_COUNT_RESET_MARGIN = 1
    }

    data class AttestationResult(
        val isTrusted: Boolean,
        val keyOrigin: HardwareKeystoreManager.KeyOrigin,
        val attestationChainPresent: Boolean,
        val attestationChainValid: Boolean,
        val bootCount: Int,
        val previousBootCount: Int?,
        val bootCountReset: Boolean,
        val reason: String,
    )

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Boot count from Settings.Global. The constant is read by its
     * string key ("boot_count") so this compiles on every API level;
     * -1 means "unavailable on this device" and must not be treated
     * as a reset.
     */
    fun getBootCount(): Int = try {
        Settings.Global.getInt(context.contentResolver, "boot_count", -1)
    } catch (e: Exception) {
        Log.w(TAG, "getBootCount failed: ${e.javaClass.simpleName}")
        -1
    }

    fun getLastSeenBootCount(): Int? =
        if (prefs.contains(KEY_LAST_BOOT_COUNT)) prefs.getInt(KEY_LAST_BOOT_COUNT, -1) else null

    fun recordBootCount(bootCount: Int) {
        if (bootCount >= 0) prefs.edit().putInt(KEY_LAST_BOOT_COUNT, bootCount).apply()
    }

    /** True if [bootCount] is unexpectedly lower than [previous] (a wipe / re-flash / rollback). */
    fun detectBootCountReset(bootCount: Int, previous: Int?): Boolean {
        if (bootCount < 0 || previous == null || previous < 0) return false
        return bootCount + BOOT_COUNT_RESET_MARGIN < previous || (previous > 0 && bootCount == 0)
    }

    /**
     * Validate the attestation chain structurally: non-empty, leaf
     * is X.509, leaf public key matches the live device public key,
     * and every certificate in the chain parses. Full chain-of-
     * trust verification against Google's attestation root belongs
     * on the BACKEND (it holds the root and the expected
     * attestation extension values); the device only checks that
     * the chain is present and self-consistent.
     */
    fun validateAttestationChain(chain: List<Certificate>): Boolean {
        if (chain.isEmpty()) return false
        val leaf = chain.firstOrNull() as? X509Certificate ?: return false
        val devicePublicKey = keystoreManager.getPublicKey() ?: return false
        if (!leaf.publicKey.encoded.contentEquals(devicePublicKey.encoded)) {
            Log.w(TAG, "Attestation leaf public key does not match device key")
            return false
        }
        // Every cert must parse as X.509; expiry is checked by the backend.
        if (chain.any { it !is X509Certificate }) return false
        return true
    }

    /**
     * Run all on-device checks and persist the current boot count.
     * `isTrusted` is true only when: the key exists, its origin is
     * hardware (TEE or StrongBox), and no boot-count reset was seen.
     * Attestation-chain absence alone does NOT make the device
     * untrusted (some AER devices omit it) — it is reported in
     * the result for the backend to weigh.
     */
    fun checkDeviceIntegrity(): AttestationResult {
        val bootCount = getBootCount()
        val previous = getLastSeenBootCount()
        val reset = detectBootCountReset(bootCount, previous)
        if (bootCount >= 0) recordBootCount(bootCount)

        val info = keystoreManager.describeKey()
        val chain = keystoreManager.getAttestationChain()
        val chainValid = if (chain.isEmpty()) false else validateAttestationChain(chain)
        val hardwareBacked =
            info.origin == HardwareKeystoreManager.KeyOrigin.TEE ||
                info.origin == HardwareKeystoreManager.KeyOrigin.STRONGBOX

        val reason = when {
            !info.exists -> "device key absent"
            reset -> "boot_count reset detected (previous=$previous, current=$bootCount)"
            !hardwareBacked -> "device key is not hardware-backed (origin=${info.origin})"
            !chainValid && chain.isNotEmpty() -> "attestation chain present but invalid"
            else -> "ok"
        }
        val trusted = info.exists && hardwareBacked && !reset
        if (!trusted) Log.w(TAG, "Integrity check failed: $reason")
        return AttestationResult(
            isTrusted = trusted,
            keyOrigin = info.origin,
            attestationChainPresent = chain.isNotEmpty(),
            attestationChainValid = chainValid,
            bootCount = bootCount,
            previousBootCount = previous,
            bootCountReset = reset,
            reason = reason,
        )
    }
}
