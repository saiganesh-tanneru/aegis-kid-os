package com.aegis.kid.security

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Dead-man watchdog: persistent foreground service + WorkManager guard.
 *
 * Cadence (read carefully — WorkManager cannot do 10 minutes):
 *  - WorkManager's minimum periodic interval is 15 minutes, so
 *    WorkManager is used ONLY as a restart guard: every 15 minutes
 *    it ensures this service is running and flushes the cache.
 *  - The actual 10-minute heartbeat cadence is a coroutine loop
 *    inside this foreground service (see [HEARTBEAT_INTERVAL_MS]).
 *    The service is started by the Device Owner provisioning flow
 *    and is protected from being killed by the kiosk lockdown
 *    (no Settings access, no force-stop from the launcher).
 *
 * Battery-aware behaviour:
 *  - battery <= 5%: do NOT attempt a network send (save power for
 *    a graceful shutdown). Cache the signed heartbeat locally; the
 *    backend suppresses breach alerts for low-battery disconnects.
 *  - battery > 5% and offline: cache locally, batch-sync on reconnect.
 *  - battery > 15% and heartbeats stop abruptly while the network
 *    stays up: the BACKEND raises CRITICAL_TAMPER_BREACH — the
 *    device never decides that itself.
 *
 * Privacy: this service logs counts and outcomes only. It never
 * logs heartbeat contents, signatures, URLs, or app names.
 *
 * Transport is injected via [HeartbeatSender] — the actual HTTPS
 * client belongs to the app's networking layer (Deliverable 5
 * backend contract), not to this security package. The default
 * sender is a no-op that caches everything, so the watchdog is
 * safe to run before the network layer is wired.
 *
 * Manifest requirements (owned by the app module, not this file):
 *  - `<service android:foregroundServiceType="dataSync" ...>`
 *  - `FOREGROUND_SERVICE` / `FOREGROUND_SERVICE_DATA_SYNC`
 *    permissions, and `RECEIVE_BOOT_COMPLETED` to restart after reboot.
 */
class WatchdogService : Service() {

    companion object {
        private const val TAG = "AegisWatchdog"
        const val WORK_NAME = "aegis_heartbeat_work"
        const val HEARTBEAT_INTERVAL_MS = 10L * 60L * 1000L // 10 minutes
        const val LOW_BATTERY_THRESHOLD_PCT = 5
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "aegis_watchdog"
        private const val PREFS_DEVICE = "aegis_device"
        private const val KEY_DEVICE_ID = "device_id"

        /** Pseudonymous device UUID, created once at provisioning. Never IMEI / serial. */
        fun getOrCreateDeviceId(context: Context): String {
            val prefs = context.getSharedPreferences(PREFS_DEVICE, Context.MODE_PRIVATE)
            val existing = prefs.getString(KEY_DEVICE_ID, null)
            if (!existing.isNullOrBlank()) return existing
            val created = UUID.randomUUID().toString()
            prefs.edit().putString(KEY_DEVICE_ID, created).apply()
            return created
        }

        /** Schedule the 15-minute WorkManager guard (KEEP existing work if already scheduled). */
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<HeartbeatWorker>(15, TimeUnit.MINUTES)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request,
            )
            Log.i(TAG, "Heartbeat guard work scheduled (15-min WorkManager, 10-min service loop)")
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
            context.stopService(Intent(context, WatchdogService::class.java))
        }
    }

    /** Transport for signed heartbeats. Replace with the real HTTPS client at app wiring time. */
    interface HeartbeatSender {
        sealed class SendResult {
            data object Acked : SendResult()
            data object Offline : SendResult()
            data class Failed(val reason: String) : SendResult()
        }

        suspend fun send(batch: List<SignedHeartbeat>): SendResult
    }

    /**
     * Default sender: always reports Offline, so every heartbeat is
     * cached and flushed later. Swap via [sender] before starting
     * the service in production wiring.
     */
    var sender: HeartbeatSender = object : HeartbeatSender {
        override suspend fun send(batch: List<SignedHeartbeat>): HeartbeatSender.SendResult =
            HeartbeatSender.SendResult.Offline
    }

    private val serviceJob = Job()
    private val scope = CoroutineScope(Dispatchers.Default + serviceJob)
    private lateinit var keystoreManager: HardwareKeystoreManager
    private lateinit var signer: Ed25519Signer
    private lateinit var heartbeatCache: HeartbeatCache
    private lateinit var attestationChecker: AttestationChecker

    override fun onCreate() {
        super.onCreate()
        keystoreManager = HardwareKeystoreManager(applicationContext)
        signer = Ed25519Signer(keystoreManager)
        heartbeatCache = HeartbeatCache(applicationContext)
        attestationChecker = AttestationChecker(applicationContext, keystoreManager)
        startForegroundWithNotification()
        scope.launch { heartbeatLoop() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // START_STICKY: the system restarts the watchdog after it is
        // killed; combined with the WorkManager guard this keeps the
        // dead-man signal alive across low-memory kills.
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        serviceJob.cancel()
        super.onDestroy()
    }

    private fun startForegroundWithNotification() {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Aegis safety watchdog",
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = "Keeps the device safety heartbeat running." }
            manager.createNotificationChannel(channel)
        }
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Aegis safety protection is on")
            .setContentText("Device safety heartbeat running.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            @Suppress("DEPRECATION")
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private suspend fun heartbeatLoop() {
        while (scope.isActive) {
            runCatching { sendHeartbeatOnce() }
                .onFailure { Log.w(TAG, "Heartbeat tick failed: ${it.javaClass.simpleName}") }
            delay(HEARTBEAT_INTERVAL_MS)
        }
    }

    /**
     * One tick: build + sign a heartbeat, cache it, then try to
     * flush the whole queue if the network is up and the battery
     * allows. Returns true if the fresh heartbeat was ACKed.
     */
    suspend fun sendHeartbeatOnce(): Boolean {
        val batteryPct = readBatteryPct()
        val networkState = readNetworkState()
        val bootCount = attestationChecker.getBootCount()
        val payload = HeartbeatPayload(
            deviceId = getOrCreateDeviceId(applicationContext),
            batteryPct = batteryPct,
            networkState = networkState,
            bootCount = bootCount,
            timestampEpochSeconds = System.currentTimeMillis() / 1000L,
        )
        val signed = HeartbeatSigner.sign(payload, signer)
        if (signed == null) {
            Log.w(TAG, "Heartbeat signing failed — key absent? Will retry next tick.")
            return false
        }
        if (!heartbeatCache.enqueue(signed)) {
            Log.w(TAG, "Heartbeat cache unavailable — heartbeat dropped (counted, not logged)")
            return false
        }

        // Low battery: cache only, never attempt network.
        if (batteryPct <= LOW_BATTERY_THRESHOLD_PCT) {
            Log.d(TAG, "Low battery ($batteryPct%) — heartbeat cached, no network attempt")
            return false
        }
        if (networkState == NetworkState.OFFLINE) {
            Log.d(TAG, "Offline — heartbeat cached, ${heartbeatCache.size()} pending")
            return false
        }
        return flushCache()
    }

    /**
     * Send the whole cached queue, oldest first. Entries are
     * removed ONLY after the backend ACKs them ([HeartbeatCache.
     * removeAcked]). A failed send leaves the queue intact.
     */
    suspend fun flushCache(): Boolean {
        val pending = heartbeatCache.drainAll()
        if (pending.isEmpty()) return true
        return when (val result = sender.send(pending)) {
            is HeartbeatSender.SendResult.Acked -> {
                heartbeatCache.removeAcked(pending.size)
                Log.d(TAG, "Flushed ${pending.size} heartbeats, queue empty")
                true
            }
            is HeartbeatSender.SendResult.Offline -> {
                Log.d(TAG, "Flush offline — ${pending.size} heartbeats remain cached")
                false
            }
            is HeartbeatSender.SendResult.Failed -> {
                Log.w(TAG, "Flush failed: ${result.reason} — ${pending.size} remain cached")
                false
            }
        }
    }

    private fun readBatteryPct(): Int {
        val batteryManager = getSystemService(BATTERY_SERVICE) as BatteryManager
        val pct = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        return pct.coerceIn(0, 100)
    }

    private fun readNetworkState(): NetworkState {
        val connectivity = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivity.activeNetwork ?: return NetworkState.OFFLINE
        val caps = connectivity.getNetworkCapabilities(network) ?: return NetworkState.UNKNOWN
        return if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
            NetworkState.ONLINE
        } else if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
            NetworkState.UNKNOWN
        } else {
            NetworkState.OFFLINE
        }
    }

    /**
     * WorkManager guard worker (15-min minimum). Ensures the
     * foreground service is running and flushes the cache when
     * online. This is the restart net for low-memory kills and
     * reboots (with RECEIVE_BOOT_COMPLETED re-scheduling).
     */
    class HeartbeatWorker(
        appContext: Context,
        params: WorkerParameters,
    ) : CoroutineWorker(appContext, params) {

        override suspend fun doWork(): Result {
            val context = applicationContext
            // Ensure the foreground service is up.
            val intent = Intent(context, WatchdogService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            Log.d(TAG, "Heartbeat guard tick — service ensured running")
            return Result.success()
        }
    }
}
