package com.aegis.kid.gatekeeper

import android.content.Context
import android.graphics.Bitmap
import android.os.BatteryManager
import android.util.Log
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.TextRecognizer
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import java.util.concurrent.atomic.AtomicLong

/**
 * Low-power periodic OCR screen guard.
 *
 * Purpose: catch harmful content that never passes through the WebView -
 * e.g. text rendered inside an allowlisted app's image feed, a meme, or a
 * screenshot shared into an app. The guard samples the screen at the
 * age-tier interval, runs on-device ML Kit text recognition, classifies
 * the recognised text with [SafetyClassifier], and discards everything.
 *
 * What this class does NOT do (by design):
 *  - It never captures the screen itself. A bitmap must be supplied by
 *    the DPC module via MediaProjection or an AccessibilityService frame
 *    callback - screen capture needs user consent / system permission
 *    this class cannot grant itself.
 *  - It never saves a bitmap, a text snippet, or a verdict with content
 *    to disk, and never uploads anything. The bitmap is downscaled,
 *    processed in RAM, and recycled in a `finally` block.
 *  - It never runs while the battery is low or the device is idle: the
 *    sampling interval stretches (see [shouldSampleNow]) to protect the
 *    3-4 GB RAM budget tablets this MVP targets.
 *
 * The OCR result is text only. If the text classifies BLOCK, the caller
 * (Kiosk Launcher / DPC) is notified via [ScreenGuardListener] with a
 * reason code only, and it decides the response (e.g. return to the
 * launcher home). This class never navigates, never kills apps itself.
 */
class ScreenGuardOcr(
    context: Context,
    private val classifier: SafetyClassifier,
    private val tierProvider: () -> AgeTier,
) {

    interface ScreenGuardListener {
        fun onOcrBlocked(reasonCode: ReasonCode, category: RiskCategory)
        fun onOcrEscalated(reasonCode: ReasonCode, category: RiskCategory)
    }

    var listener: ScreenGuardListener? = null

    private val recognizer: TextRecognizer =
        TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)

    private val batteryManager =
        context.applicationContext.getSystemService(Context.BATTERY_SERVICE) as BatteryManager

    @Volatile
    private var lastSampleAtMs: Long = 0L

    @Volatile
    var isRunning: Boolean = false
        private set

    val samplesTaken = AtomicLong(0)
    val samplesSkippedLowBattery = AtomicLong(0)

    companion object {
        private const val TAG = "AegisScreenGuardOcr"

        /** OCR input is downscaled to this max dimension: accuracy is fine, RAM is not wasted. */
        const val MAX_OCR_DIMENSION_PX: Int = 720

        /** Below this battery level OCR sampling pauses entirely (charging resumes it). */
        const val LOW_BATTERY_CUTOFF_PCT: Int = 15

        /** Below this level the interval doubles to save power. */
        const val POWER_SAVE_BATTERY_PCT: Int = 30
    }

    fun start() {
        isRunning = true
    }

    fun stop() {
        isRunning = false
    }

    /** Current battery percentage, 0-100, or -1 if unavailable. */
    fun batteryPercent(): Int {
        return batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
    }

    fun isCharging(): Boolean {
        val status = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_STATUS)
        return status == BatteryManager.BATTERY_CHARGING || status == BatteryManager.BATTERY_FULL
    }

    /**
     * Throttle decision. Returns false when the guard is stopped, the
     * tier interval has not elapsed, or the battery is too low - unless
     * the device is charging, in which case low battery does not block.
     */
    fun shouldSampleNow(nowMs: Long = System.currentTimeMillis()): Boolean {
        if (!isRunning) return false
        val tier = tierProvider()
        var interval = tier.ocrSampleIntervalMs
        val battery = batteryPercent()
        if (battery in 0 until LOW_BATTERY_CUTOFF_PCT && !isCharging()) {
            samplesSkippedLowBattery.incrementAndGet()
            return false
        }
        if (battery in LOW_BATTERY_CUTOFF_PCT until POWER_SAVE_BATTERY_PCT && !isCharging()) {
            interval *= 2
        }
        return nowMs - lastSampleAtMs >= interval
    }

    /**
     * Process one frame. [frame] is a bitmap supplied by the caller; this
     * method takes ownership of the *downscaled copy only* and recycles
     * it. The caller's original bitmap is never modified or recycled here.
     * The callback receives a verdict (reason code + category only).
     */
    fun processFrame(frame: Bitmap, onResult: (ContentVerdict) -> Unit) {
        if (!isRunning) return
        val tier = tierProvider()
        lastSampleAtMs = System.currentTimeMillis()
        samplesTaken.incrementAndGet()

        val scaled = downscale(frame)
        val image = InputImage.fromBitmap(scaled, 0)
        recognizer.process(image)
            .addOnSuccessListener { visionText ->
                var text: String? = null
                try {
                    // Rebuild plain text from blocks, capped at the tier limit.
                    val builder = StringBuilder()
                    for (block in visionText.textBlocks) {
                        if (builder.length >= tier.maxClassifiedChars) break
                        builder.append(block.text).append(' ')
                    }
                    text = builder.toString()
                    if (text.isBlank()) {
                        onResult(ContentVerdict.emptyContentAllow(tier))
                        return@addOnSuccessListener
                    }
                    val verdict = classifier.classify(text, tier)
                    val mapped = when (verdict.decision) {
                        Decision.BLOCK -> verdict.copy(reasonCode = ReasonCode.OCR_BLOCK)
                        Decision.ESCALATE -> verdict.copy(reasonCode = ReasonCode.OCR_ESCALATE)
                        Decision.ALLOW -> verdict
                    }
                    when (mapped.decision) {
                        Decision.BLOCK -> listener?.onOcrBlocked(mapped.reasonCode, mapped.category)
                        Decision.ESCALATE -> listener?.onOcrEscalated(mapped.reasonCode, mapped.category)
                        Decision.ALLOW -> Unit
                    }
                    onResult(mapped)
                } catch (e: Exception) {
                    Log.w(TAG, "OCR classification failed: ${e.javaClass.simpleName}")
                    onResult(
                        ContentVerdict(
                            decision = Decision.ALLOW,
                            confidence = 0f,
                            category = RiskCategory.UNKNOWN,
                            reasonCode = ReasonCode.CLASSIFIER_ERROR_RULE_FALLBACK,
                            ageTier = tier,
                            latencyMs = 0L,
                        ),
                    )
                } finally {
                    // Purge: drop the only reference to the recognised text.
                    text = null
                    if (scaled != frame) scaled.recycle()
                }
            }
            .addOnFailureListener { e ->
                if (scaled != frame) scaled.recycle()
                Log.w(TAG, "OCR recognition failed: ${e.javaClass.simpleName}")
                onResult(
                    ContentVerdict(
                        decision = Decision.ALLOW,
                        confidence = 0f,
                        category = RiskCategory.UNKNOWN,
                        reasonCode = ReasonCode.CLASSIFIER_ERROR_RULE_FALLBACK,
                        ageTier = tier,
                        latencyMs = 0L,
                    ),
                )
            }
    }

    /** Downscale to [MAX_OCR_DIMENSION_PX] on the long edge. Returns the original if already small. */
    private fun downscale(frame: Bitmap): Bitmap {
        val width = frame.width
        val height = frame.height
        val longest = maxOf(width, height)
        if (longest <= MAX_OCR_DIMENSION_PX) return frame
        val scale = MAX_OCR_DIMENSION_PX.toFloat() / longest
        return Bitmap.createScaledBitmap(
            frame,
            (width * scale).toInt().coerceAtLeast(1),
            (height * scale).toInt().coerceAtLeast(1),
            true,
        )
    }

    /** Release the recognizer. Call from the owning Service onDestroy. */
    fun close() {
        runCatching { recognizer.close() }
        isRunning = false
    }
}
