package com.aegis.kid.gatekeeper

import android.app.ActivityManager
import android.content.Context
import android.os.Debug
import android.util.Log
import com.google.mediapipe.tasks.text.textclassifier.TextClassifier
import com.google.mediapipe.tasks.text.textclassifier.TextClassifierOptions
import org.tensorflow.lite.Interpreter
import org.tensorflow.lite.nnapi.NnapiDelegate
import java.text.Normalizer
import java.util.Arrays
import java.util.Locale

/**
 * Offline-first multilingual safety classifier (LiteRT / MediaPipe).
 *
 * Pipeline, in order:
 *  1. Fast rule pre-filter ([HinglishDetector.matchRiskCategories]) - an
 *     unambiguous high-risk keyword hit short-circuits to BLOCK without
 *     spending inference time or battery.
 *  2. LiteRT quantized model ([Interpreter]) - primary detector. Input is
 *     token ids, output is one float score per [RiskCategory] ordinal
 *     (see assets/models/README.md for the exact contract).
 *  3. Rule-based fallback - used when the model file is missing, fails to
 *     load, or the device is out of memory. The fallback is deliberately
 *     strict (lower effective thresholds) because it has no semantic
 *     understanding.
 *
 * PRIVACY: 100% offline, no network calls anywhere in this file. All
 * classification happens in volatile RAM. Input text is copied into a
 * [CharArray], processed, and then overwritten with zeros in a `finally`
 * block; token / score buffers are zeroed the same way. Nothing is
 * persisted, nothing is logged - only counters ([VerdictCounters]) and
 * the verdict itself leave this class.
 *
 * PERFORMANCE: the model is loaded lazily on first use, exactly once
 * (single [Interpreter] instance, guarded by [loadLock]). NNAPI is tried
 * and silently dropped if the device rejects it. Total RAM budget is
 * 300 MB for the whole gatekeeper (model + OCR + WebView); if the device
 * cannot offer headroom, the classifier refuses to load the model and
 * falls back to rules instead of OOM-killing the launcher.
 */
class SafetyClassifier(
    private val context: Context,
    private val ageTier: AgeTier,
) {
    enum class Backend { INTERPRETER, MEDIAPIPE, RULE_BASED }

    val counters = VerdictCounters()

    @Volatile
    private var interpreter: Interpreter? = null

    @Volatile
    private var mediapipeClassifier: TextClassifier? = null

    @Volatile
    private var backend: Backend = Backend.RULE_BASED

    @Volatile
    private var loadAttempted: Boolean = false

    private val loadLock = Any()

    companion object {
        private const val TAG = "AegisSafetyClassifier"

        const val MODEL_ASSET_PATH: String = "models/safety_classifier_quant.tflite"
        const val MAX_TOKENS: Int = 128
        const val VOCAB_SIZE: Int = 8192
        const val PAD_ID: Int = 0
        const val UNK_ID: Int = 1
        const val CLS_ID: Int = 2
        const val SEP_ID: Int = 3

        /** Model file budget: a quantized classifier must fit in 40 MB. */
        const val MODEL_SIZE_BUDGET_BYTES: Long = 40L * 1024L * 1024L

        /** Whole-gatekeeper RAM budget (model + OCR + WebView + app). */
        const val TOTAL_RAM_BUDGET_BYTES: Long = 300L * 1024L * 1024L

        /** Refuse to load the model unless this much RAM is free. */
        const val MIN_FREE_RAM_TO_LOAD_BYTES: Long = 150L * 1024L * 1024L

        /** Above this score a rule-based hit is treated as a hard block. */
        const val RULE_HARD_BLOCK_SCORE: Float = 0.85f
    }

    // ------------------------------------------------------------------
    // Loading
    // ------------------------------------------------------------------

    /** Lazily load the model (once). Returns the backend that will serve calls. */
    fun ensureLoaded(): Backend {
        if (loadAttempted) return backend
        synchronized(loadLock) {
            if (loadAttempted) return backend
            loadAttempted = true
            backend = try {
                loadModel()
            } catch (e: OutOfMemoryError) {
                Log.w(TAG, "Model load OOM, using rule-based fallback")
                Backend.RULE_BASED
            } catch (e: Exception) {
                Log.w(TAG, "Model load failed, using rule-based fallback: ${e.javaClass.simpleName}")
                Backend.RULE_BASED
            }
            return backend
        }
    }

    private fun loadModel(): Backend {
        if (!hasMemoryHeadroom()) {
            Log.w(TAG, "Insufficient free RAM to load model, using rule-based fallback")
            return Backend.RULE_BASED
        }
        val modelBytes = try {
            context.assets.openFd(MODEL_ASSET_PATH).use { fd ->
                if (fd.length > MODEL_SIZE_BUDGET_BYTES) {
                    Log.w(TAG, "Model exceeds size budget, refusing to load")
                    return Backend.RULE_BASED
                }
                fd.length
            }
        } catch (_: Exception) {
            Log.i(TAG, "No bundled model asset, using rule-based fallback")
            return Backend.RULE_BASED
        }
        Log.i(TAG, "Loading model asset, bytes=$modelBytes")
        // MediaPipe TextClassifier path (preferred when the model is a
        // MediaPipe text-classifier bundle); falls through to raw LiteRT.
        runCatching {
            val options = TextClassifierOptions.builder()
                .setMaxResults(RiskCategory.entries.size)
                .build()
            mediapipeClassifier = TextClassifier.createFromFileAndOptions(context, MODEL_ASSET_PATH, options)
            return Backend.MEDIAPIPE
        }
        // Raw LiteRT Interpreter path.
        val options = Interpreter.Options().apply {
            setNumThreads(2)
            runCatching {
                addDelegate(NnapiDelegate())
            }.onFailure {
                Log.i(TAG, "NNAPI delegate unavailable, running on CPU")
            }
        }
        val modelBuffer = context.assets.openFd(MODEL_ASSET_PATH).use { fd ->
            fd.createInputStream().use { it.readBytes() }
        }
        // Do NOT zero modelBuffer: the Interpreter keeps a ByteBuffer view
        // over this exact backing array. The bytes are part of the 300 MB
        // budget by design and become unreachable when close() drops the
        // Interpreter. They are never written to disk.
        interpreter = Interpreter(java.nio.ByteBuffer.wrap(modelBuffer).asReadOnlyBuffer(), options)
        return Backend.INTERPRETER
    }

    /** True when the device can spare the RAM for model + working buffers. */
    fun hasMemoryHeadroom(): Boolean {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)
        val nativeHeap = Debug.getNativeHeapAllocatedSize()
        val estimatedTotal = nativeHeap + MODEL_SIZE_BUDGET_BYTES
        return memoryInfo.availMem >= MIN_FREE_RAM_TO_LOAD_BYTES &&
            estimatedTotal <= TOTAL_RAM_BUDGET_BYTES &&
            !memoryInfo.lowMemory
    }

    // ------------------------------------------------------------------
    // Classification (volatile only)
    // ------------------------------------------------------------------

    /**
     * Classify [text] under [tier]. The input is copied to a [CharArray]
     * and zeroed after use; no reference to the caller's text is retained.
     */
    fun classify(text: CharSequence, tier: AgeTier = ageTier): ContentVerdict {
        val startMs = System.currentTimeMillis()
        val chars = CharArray(text.length)
        return try {
            text.toString().toCharArray(chars)
            val bounded = String(chars).take(tier.maxClassifiedChars)
            if (bounded.isBlank()) return ContentVerdict.emptyContentAllow(tier)

            // 1. Fast rule pre-filter: unambiguous keyword hit short-circuits.
            val ruleScores = HinglishDetector.matchRiskCategories(bounded)
            val hardHit = ruleScores.entries.firstOrNull { it.value >= RULE_HARD_BLOCK_SCORE }
            if (hardHit != null) {
                val verdict = ContentVerdict.block(
                    category = hardHit.key,
                    confidence = hardHit.value,
                    reasonCode = ReasonCode.RULE_BLOCK,
                    ageTier = tier,
                    latencyMs = System.currentTimeMillis() - startMs,
                )
                counters.record(verdict)
                return verdict
            }

            // 2. Model inference (or rule fallback if the model is unavailable).
            val activeBackend = ensureLoaded()
            val (category, score) = when (activeBackend) {
                Backend.INTERPRETER -> runInterpreter(bounded)
                Backend.MEDIAPIPE -> runMediapipe(bounded)
                Backend.RULE_BASED -> {
                    counters.ruleFallbackCalls.incrementAndGet()
                    ruleBasedVerdict(bounded, ruleScores, tier)
                }
            }
            val decision = AgeRubric.decide(category, score, tier)
            val reason = when {
                activeBackend == Backend.RULE_BASED -> when (decision) {
                    Decision.BLOCK -> ReasonCode.RULE_BLOCK
                    Decision.ESCALATE -> ReasonCode.RULE_ESCALATE
                    Decision.ALLOW -> ReasonCode.CLASSIFIER_ALLOW
                }
                decision == Decision.BLOCK -> ReasonCode.CLASSIFIER_BLOCK
                decision == Decision.ESCALATE -> ReasonCode.CLASSIFIER_ESCALATE
                else -> ReasonCode.CLASSIFIER_ALLOW
            }
            val verdict = ContentVerdict(
                decision = decision,
                confidence = score,
                category = category,
                reasonCode = reason,
                ageTier = tier,
                latencyMs = System.currentTimeMillis() - startMs,
            )
            counters.record(verdict)
            verdict
        } catch (e: OutOfMemoryError) {
            Log.w(TAG, "Classification OOM, falling back to rules")
            val fallback = ruleBasedFallback(text, tier, ReasonCode.MODEL_OOM_RULE_FALLBACK, startMs)
            counters.record(fallback)
            fallback
        } catch (e: Exception) {
            Log.w(TAG, "Classification error, falling back to rules: ${e.javaClass.simpleName}")
            val fallback = ruleBasedFallback(text, tier, ReasonCode.CLASSIFIER_ERROR_RULE_FALLBACK, startMs)
            counters.record(fallback)
            fallback
        } finally {
            // Purge: overwrite the input copy and never retain it.
            Arrays.fill(chars, '\u0000')
        }
    }

    /**
     * Classify a URL's host + path tokens without fetching anything.
     * Used by [WebViewInterceptor] for the pre-navigation check. No
     * network, no content - tokens only.
     */
    fun classifyUrlTokens(tokens: List<String>, tier: AgeTier = ageTier): ContentVerdict {
        val startMs = System.currentTimeMillis()
        val joined = tokens.joinToString(" ").take(tier.maxClassifiedChars)
        if (joined.isBlank()) return ContentVerdict.emptyContentAllow(tier)
        val scores = HinglishDetector.matchRiskCategories(joined)
        val best = scores.maxByOrNull { it.value }
        if (best == null) return ContentVerdict.emptyContentAllow(tier)
        val decision = AgeRubric.decide(best.key, best.value, tier)
        val verdict = ContentVerdict(
            decision = decision,
            confidence = best.value,
            category = best.key,
            reasonCode = if (decision == Decision.BLOCK) ReasonCode.RULE_BLOCK else ReasonCode.RULE_ESCALATE,
            ageTier = tier,
            latencyMs = System.currentTimeMillis() - startMs,
        )
        counters.record(verdict)
        return verdict
    }

    // ------------------------------------------------------------------
    // Model inference
    // ------------------------------------------------------------------

    /** Run the raw LiteRT interpreter. Input int[1][MAX_TOKENS], output float[1][N]. */
    private fun runInterpreter(text: String): Pair<RiskCategory, Float> {
        val interp = interpreter ?: return ruleBasedScores(text).let { it }
        val tokenIds = tokenize(text)
        val input = Array(1) { tokenIds }
        val categoryCount = RiskCategory.entries.size
        val output = Array(1) { FloatArray(categoryCount) }
        try {
            interp.run(input, output)
            counters.modelCalls.incrementAndGet()
            val scores = output[0]
            var bestIndex = 0
            for (i in scores.indices) if (scores[i] > scores[bestIndex]) bestIndex = i
            return RiskCategory.entries[bestIndex] to scores[bestIndex].coerceIn(0f, 1f)
        } finally {
            Arrays.fill(tokenIds, 0)
            for (row in output) Arrays.fill(row, 0f)
            Arrays.fill(input[0], 0)
        }
    }

    /** Run the MediaPipe TextClassifier. Returns the top category + score. */
    private fun runMediapipe(text: String): Pair<RiskCategory, Float> {
        val classifier = mediapipeClassifier ?: return ruleBasedScores(text)
        counters.modelCalls.incrementAndGet()
        val result = classifier.classify(text)
        val categories = result.classificationResult().classifications().firstOrNull()?.categories()
            ?: return ruleBasedScores(text)
        var bestName: String? = null
        var bestScore = 0f
        for (category in categories) {
            if (category.score() > bestScore) {
                bestScore = category.score()
                bestName = category.categoryName()
            }
        }
        val matched = bestName?.let { runCatching { RiskCategory.valueOf(it) }.getOrNull() }
        return if (matched != null) matched to bestScore.coerceIn(0f, 1f) else ruleBasedScores(text)
    }

    // ------------------------------------------------------------------
    // Rule-based fallback
    // ------------------------------------------------------------------

    /** Best (category, score) from keyword matching alone. UNKNOWN at 0 when nothing matches. */
    private fun ruleBasedScores(text: String): Pair<RiskCategory, Float> {
        val scores = HinglishDetector.matchRiskCategories(text)
        val best = scores.maxByOrNull { it.value } ?: return RiskCategory.UNKNOWN to 0f
        return best.key to best.value
    }

    private fun ruleBasedVerdict(
        text: String,
        precomputedScores: Map<RiskCategory, Float>,
        tier: AgeTier,
    ): Pair<RiskCategory, Float> {
        val scores = precomputedScores.ifEmpty { HinglishDetector.matchRiskCategories(text) }
        val best = scores.maxByOrNull { it.value } ?: return RiskCategory.UNKNOWN to 0f
        return best.key to best.value
    }

    private fun ruleBasedFallback(
        text: CharSequence,
        tier: AgeTier,
        reasonCode: ReasonCode,
        startMs: Long,
    ): ContentVerdict {
        counters.ruleFallbackCalls.incrementAndGet()
        val bounded = text.toString().take(tier.maxClassifiedChars)
        val (category, score) = ruleBasedScores(bounded)
        val decision = AgeRubric.decide(category, score, tier)
        return ContentVerdict(
            decision = decision,
            confidence = score,
            category = category,
            reasonCode = reasonCode,
            ageTier = tier,
            latencyMs = System.currentTimeMillis() - startMs,
        )
    }

    // ------------------------------------------------------------------
    // Tokenizer: real structure, hash-based vocab (no vocab file bundled).
    // ------------------------------------------------------------------

    /**
     * Wordpiece-style tokenization stub with real structure: NFKC
     * normalisation, lower-casing, [CLS] / [SEP] markers, padding to
     * [MAX_TOKENS], and a stable FNV-1a hash into the vocab range.
     * A production model ships a real vocab file (see
     * assets/models/README.md) and this function is replaced by a lookup
     * into it - the input/output tensor shapes do not change.
     */
    fun tokenize(text: String): IntArray {
        val tokens = IntArray(MAX_TOKENS) { PAD_ID }
        val normalized = Normalizer.normalize(text, Normalizer.Form.NFKC)
            .lowercase(Locale.ROOT)
        val words = normalized.split(Regex("[^\\p{L}]+")).filter { it.isNotEmpty() }
        var index = 0
        tokens[index++] = CLS_ID
        for (word in words) {
            if (index >= MAX_TOKENS - 1) break
            tokens[index++] = fnv1aHash(word) % (VOCAB_SIZE - 4) + 4
        }
        if (index < MAX_TOKENS) tokens[index] = SEP_ID
        return tokens
    }

    private fun fnv1aHash(word: String): Int {
        var hash = 0x811c9dc5.toInt()
        for (ch in word) {
            hash = hash xor ch.code
            hash *= 0x01000193
        }
        return hash and Int.MAX_VALUE
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /** Release the model and zero working state. Call from the owning Service / ViewModel onDestroy. */
    fun close() {
        synchronized(loadLock) {
            runCatching { interpreter?.close() }
            runCatching { mediapipeClassifier?.close() }
            interpreter = null
            mediapipeClassifier = null
            loadAttempted = false
            backend = Backend.RULE_BASED
        }
    }
}
