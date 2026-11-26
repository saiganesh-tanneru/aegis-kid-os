package com.aegis.kid.gatekeeper

import java.util.concurrent.atomic.AtomicLong

/**
 * The only verdict type in the gatekeeper. A verdict carries scores and a
 * reason code - it NEVER carries the raw text, image, URL, or any child PII
 * that produced it. Verdicts may be counted (see [VerdictCounters]) and may
 * be shown to the child as a generic block page, but the underlying content
 * is purged immediately after the verdict is produced.
 */
enum class Decision {
    ALLOW,
    BLOCK,
    /** No local override. Route to the Cloud AI Safety Adjudicator / Human Support queue. */
    ESCALATE,
}

/** Machine-readable reason for a verdict. Safe to log and to show on a block page. */
enum class ReasonCode {
    ALLOWLISTED_EDTECH,
    ALLOWLISTED_DOMAIN,
    CLASSIFIER_ALLOW,
    CLASSIFIER_BLOCK,
    CLASSIFIER_ESCALATE,
    RULE_BLOCK,
    RULE_ESCALATE,
    OCR_BLOCK,
    OCR_ESCALATE,
    SEARCH_ENGINE_BLOCK,
    FINANCIAL_APP_BLOCK,
    SCHEME_BLOCK,
    DOMAIN_NOT_ALLOWLISTED,
    DOWNLOAD_BLOCK,
    JS_BRIDGE_BLOCK,
    MODEL_UNAVAILABLE_RULE_FALLBACK,
    MODEL_OOM_RULE_FALLBACK,
    CLASSIFIER_ERROR_RULE_FALLBACK,
    EMPTY_CONTENT_ALLOW,
}

/**
 * Immutable result of one classification. [confidence] is the winning
 * category score in [0, 1]. [latencyMs] is classifier time only.
 * Deliberately no `text`, `url`, `host`, or `bitmap` field exists here.
 */
data class ContentVerdict(
    val decision: Decision,
    val confidence: Float,
    val category: RiskCategory,
    val reasonCode: ReasonCode,
    val ageTier: AgeTier,
    val latencyMs: Long,
    val evaluatedAtEpochMs: Long = System.currentTimeMillis(),
) {
    companion object {
        fun allow(
            category: RiskCategory,
            confidence: Float,
            reasonCode: ReasonCode,
            ageTier: AgeTier,
            latencyMs: Long,
        ) = ContentVerdict(Decision.ALLOW, confidence, category, reasonCode, ageTier, latencyMs)

        fun block(
            category: RiskCategory,
            confidence: Float,
            reasonCode: ReasonCode,
            ageTier: AgeTier,
            latencyMs: Long,
        ) = ContentVerdict(Decision.BLOCK, confidence, category, reasonCode, ageTier, latencyMs)

        fun escalate(
            category: RiskCategory,
            confidence: Float,
            reasonCode: ReasonCode,
            ageTier: AgeTier,
            latencyMs: Long,
        ) = ContentVerdict(Decision.ESCALATE, confidence, category, reasonCode, ageTier, latencyMs)

        /** Used when there is nothing to classify (empty page, image-only page with no OCR text). */
        fun emptyContentAllow(ageTier: AgeTier) = ContentVerdict(
            decision = Decision.ALLOW,
            confidence = 0f,
            category = RiskCategory.UNKNOWN,
            reasonCode = ReasonCode.EMPTY_CONTENT_ALLOW,
            ageTier = ageTier,
            latencyMs = 0L,
        )
    }
}

/**
 * Privacy-safe telemetry: counters only. No URLs, hosts, search queries,
 * text snippets, or per-child identifiers are ever recorded here.
 */
class VerdictCounters {
    val allowed = AtomicLong(0)
    val blocked = AtomicLong(0)
    val escalated = AtomicLong(0)
    val classifierCalls = AtomicLong(0)
    val ruleFallbackCalls = AtomicLong(0)
    val modelCalls = AtomicLong(0)

    fun record(verdict: ContentVerdict) {
        classifierCalls.incrementAndGet()
        when (verdict.decision) {
            Decision.ALLOW -> allowed.incrementAndGet()
            Decision.BLOCK -> blocked.incrementAndGet()
            Decision.ESCALATE -> escalated.incrementAndGet()
        }
    }

    /** Snapshot for the (zero-PII) watchdog heartbeat: counts only, never content. */
    fun snapshot(): Map<String, Long> = mapOf(
        "allowed" to allowed.get(),
        "blocked" to blocked.get(),
        "escalated" to escalated.get(),
        "classifier_calls" to classifierCalls.get(),
        "rule_fallback_calls" to ruleFallbackCalls.get(),
        "model_calls" to modelCalls.get(),
    )
}
