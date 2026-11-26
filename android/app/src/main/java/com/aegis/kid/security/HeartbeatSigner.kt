package com.aegis.kid.security

import org.json.JSONObject
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Dead-man heartbeat payload.
 *
 * EXACTLY these fields are transmitted, nothing else — this is the
 * entire telemetry the backend ever receives from the device, and it
 * contains zero child PII: no browsing history, no app usage, no
 * location, no screenshots, no search queries, no voice/text.
 *
 * Wire format (JSON object sent to POST /api/v1/heartbeat —
 * backend `models.Heartbeat`):
 *   {
 *     "device_id":            "<pseudonymous UUID>",
 *     "keystore_signature":   "<Base64 signature over canonical JSON>",
 *     "battery_pct":          0-100,
 *     "network_state":        "online" | "offline" | "unknown",
 *     "boot_count":           <int, >= 0>,
 *     "timestamp":            "<ISO-8601 UTC, e.g. 2026-11-26T10:00:00+00:00>"
 *   }
 *
 * WIRE CONTRACT — signed bytes vs transmitted fields (Deliverable 5,
 * `backend/app/crypto.py::heartbeat_payload`):
 *  - SIGNED: canonical JSON `{"battery_pct":..,"boot_count":..,
 *    "device_id":"..","timestamp":"<ISO>"}`
 *    (keys sorted, no spaces). `network_state` is transmitted but
 *    NOT signed — the backend does not include it in the signed
 *    payload, so signing it would break verification.
 *  - `timestamp` is an ISO-8601 string, not epoch seconds: the
 *    backend model declares `timestamp: datetime` and re-derives
 *    the signed bytes with `timestamp.isoformat()`. The string is
 *    produced WITHOUT microseconds (whole seconds), so the backend's
 *    parse-then-reformat round-trips byte-identically.
 *  - `boot_count` must be >= 0 (backend `ge=0`). If
 *    `Settings.Global.BOOT_COUNT` is unavailable (-1), the wire
 *    value is clamped to 0 via [bootCountForWire] and the
 *    unavailability is visible to the backend as boot_count=0
 *    (see SECURITY.md §6).
 *
 * Canonical JSON is built by [canonicalJson] with fixed alphabetical
 * field order and no whitespace, so the backend can reproduce the
 * exact bytes. Do NOT sign `JSONObject.toString()` — its key order
 * is not guaranteed.
 */
enum class NetworkState(val wireValue: String) {
    ONLINE("online"),
    OFFLINE("offline"),
    UNKNOWN("unknown"),
}

data class HeartbeatPayload(
    val deviceId: String,
    val batteryPct: Int,
    val networkState: NetworkState,
    val bootCount: Int,
    val timestampEpochSeconds: Long,
) {
    init {
        require(deviceId.isNotBlank()) { "deviceId must not be blank" }
        require(batteryPct in 0..100) { "batteryPct must be 0..100" }
    }

    /** ISO-8601 UTC timestamp, whole seconds ("...+00:00"), matching Python `datetime.isoformat()`. */
    val timestampIso: String
        get() = OffsetDateTime.ofInstant(Instant.ofEpochSecond(timestampEpochSeconds), ZoneOffset.UTC)
            .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)

    /** Wire value for boot_count: backend requires >= 0; -1 (unavailable) clamps to 0. */
    val bootCountForWire: Int
        get() = bootCount.coerceAtLeast(0)
}

data class SignedHeartbeat(
    val payload: HeartbeatPayload,
    /** Base64 signature over [HeartbeatSigner.canonicalJson]. Null only if signing failed (never sent). */
    val signatureBase64: String?,
) {
    /** Full wire JSON, including the signature field. Timestamp is an ISO string, per the backend model. */
    fun toJson(): JSONObject = JSONObject().apply {
        put("device_id", payload.deviceId)
        put("keystore_signature", signatureBase64)
        put("battery_pct", payload.batteryPct)
        put("network_state", payload.networkState.wireValue)
        put("boot_count", payload.bootCountForWire)
        put("timestamp", payload.timestampIso)
    }

    override fun toString(): String =
        "SignedHeartbeat(deviceId=${HardwareKeystoreManager.truncated(payload.deviceId)}, " +
            "batteryPct=${payload.batteryPct}, networkState=${payload.networkState}, " +
            "bootCount=${payload.bootCount}, timestamp=${payload.timestampEpochSeconds})"
}

object HeartbeatSigner {

    /**
     * Deterministic canonical JSON for signing — backend
     * `heartbeat_payload(...)`. Field order is alphabetical;
     * numbers are bare; strings are JSON-escaped. `network_state`
     * is deliberately EXCLUDED (see class KDoc).
     * The backend MUST verify against these exact bytes.
     */
    fun canonicalJson(payload: HeartbeatPayload): String {
        val deviceId = JSONObject.quote(payload.deviceId)
        val timestamp = JSONObject.quote(payload.timestampIso)
        return """{"battery_pct":${payload.batteryPct},"boot_count":${payload.bootCountForWire},"device_id":$deviceId,"timestamp":$timestamp}"""
    }

    /** Build + sign a heartbeat. Returns null if signing fails (caller must cache/retry, never send unsigned). */
    fun sign(payload: HeartbeatPayload, signer: Ed25519Signer): SignedHeartbeat? {
        val signature = signer.signUtf8(canonicalJson(payload)) ?: return null
        return SignedHeartbeat(payload = payload, signatureBase64 = signature)
    }

    /** Parse a cached signed heartbeat back from its wire JSON. Returns null if malformed. Accepts ISO or epoch timestamps. */
    fun parse(json: String): SignedHeartbeat? = try {
        val obj = JSONObject(json)
        val network = when (obj.optString("network_state")) {
            "online" -> NetworkState.ONLINE
            "offline" -> NetworkState.OFFLINE
            else -> NetworkState.UNKNOWN
        }
        val timestampEpochSeconds = when (val raw = obj.opt("timestamp")) {
            is Number -> raw.toLong()
            is String -> PolicyToken.parseIsoToEpoch(raw) ?: return null
            else -> return null
        }
        val payload = HeartbeatPayload(
            deviceId = obj.getString("device_id"),
            batteryPct = obj.getInt("battery_pct"),
            networkState = network,
            bootCount = obj.getInt("boot_count"),
            timestampEpochSeconds = timestampEpochSeconds,
        )
        SignedHeartbeat(payload = payload, signatureBase64 = obj.optString("keystore_signature").takeIf { it.isNotBlank() })
    } catch (_: Exception) {
        null
    }
}
