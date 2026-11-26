package com.aegis.kid.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray

/**
 * Offline-resilient heartbeat cache.
 *
 * When the device is offline (train, travel, Wi-Fi off), signed
 * heartbeats are stored locally in ENCRYPTED storage and batch-
 * synced on reconnection. The queue is FIFO with a hard cap; the
 * oldest entries are dropped first when full, because a stale
 * heartbeat is worthless and an unbounded queue is a storage
 * exhaustion vector on a 3 GB tablet.
 *
 * Storage: EncryptedSharedPreferences (AES256_GCM) holding ONE
 * key — a JSON array of wire-format signed heartbeats. No
 * heartbeat content is ever written to plaintext storage or logs;
 * only the queue size is logged.
 *
 * Cap: 288 entries = 48 hours at one heartbeat per 10 minutes.
 * The backend's dead-man logic already escalates long before
 * 48 hours, so anything older than that has no alert value.
 *
 * Thread-safety: all public methods are synchronised on `lock`.
 * Purge-after-ACK is the only removal path besides [clear] on
 * unenrollment — entries are never silently dropped except by
 * the FIFO cap, which is logged as a count.
 */
class HeartbeatCache(context: Context) {

    companion object {
        private const val TAG = "AegisHeartbeatCache"
        private const val PREFS_NAME = "aegis_heartbeat_cache"
        private const val KEY_QUEUE = "signed_heartbeat_queue_v1"
        /** 48 hours of 10-minute heartbeats. */
        const val MAX_CACHED = 288
    }

    private val lock = Any()

    private val prefs: SharedPreferences? = try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    } catch (e: Exception) {
        // Fail closed: do NOT fall back to plaintext SharedPreferences.
        // Heartbeats carry a device signature; storing them in the
        // clear would let a tampered device replay them trivially.
        Log.e(TAG, "EncryptedSharedPreferences unavailable: ${e.javaClass.simpleName}")
        null
    }

    /** Number of cached (unsynced) heartbeats. */
    fun size(): Int = synchronized(lock) { readQueue().size }

    /** Append a signed heartbeat. Returns false if storage is unavailable. */
    fun enqueue(heartbeat: SignedHeartbeat): Boolean {
        val prefs = prefs ?: return false
        synchronized(lock) {
            val queue = readQueue().toMutableList()
            queue.add(heartbeat.toJson().toString())
            // FIFO cap: drop oldest first.
            var dropped = 0
            while (queue.size > MAX_CACHED) {
                queue.removeAt(0)
                dropped++
            }
            if (dropped > 0) Log.w(TAG, "Heartbeat queue full, dropped $dropped oldest entries")
            prefs.edit().putString(KEY_QUEUE, JSONArray(queue).toString()).apply()
            return true
        }
    }

    /**
     * Return all cached heartbeats, oldest first, WITHOUT removing
     * them. The caller sends them, then calls [removeAcked] with
     * the count the backend acknowledged. Never clear on send —
     * only on ACK — or an interrupted sync loses heartbeats.
     */
    fun drainAll(): List<SignedHeartbeat> = synchronized(lock) {
        readQueue().mapNotNull { HeartbeatSigner.parse(it) }
    }

    /** Remove the oldest [count] entries after backend ACK. */
    fun removeAcked(count: Int) {
        if (count <= 0) return
        val prefs = prefs ?: return
        synchronized(lock) {
            val queue = readQueue().toMutableList()
            val removed = minOf(count, queue.size)
            repeat(removed) { queue.removeAt(0) }
            prefs.edit().putString(KEY_QUEUE, JSONArray(queue).toString()).apply()
            Log.d(TAG, "Removed $removed ACKed heartbeats, ${queue.size} remain")
        }
    }

    /** Remove entries up to and including [timestampEpochSeconds] (alternative ACK-by-time path). */
    fun removeAckedUpTo(timestampEpochSeconds: Long) {
        val prefs = prefs ?: return
        synchronized(lock) {
            val queue = readQueue()
            val remaining = queue.filter { raw ->
                (HeartbeatSigner.parse(raw)?.payload?.timestampEpochSeconds ?: Long.MAX_VALUE) > timestampEpochSeconds
            }
            prefs.edit().putString(KEY_QUEUE, JSONArray(remaining).toString()).apply()
        }
    }

    /** Delete everything — unenrollment only (see [HardwareKeystoreManager.purgeOnUnenrollment]). */
    fun clear() {
        val prefs = prefs ?: return
        synchronized(lock) {
            prefs.edit().remove(KEY_QUEUE).apply()
            Log.i(TAG, "Heartbeat cache cleared")
        }
    }

    private fun readQueue(): List<String> {
        val prefs = prefs ?: return emptyList()
        val raw = prefs.getString(KEY_QUEUE, null) ?: return emptyList()
        return try {
            val array = JSONArray(raw)
            List(array.length()) { i -> array.getString(i) }
        } catch (_: Exception) {
            Log.w(TAG, "Heartbeat queue corrupt, discarding cached entries")
            emptyList()
        }
    }
}
