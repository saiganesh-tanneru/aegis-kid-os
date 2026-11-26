package com.aegis.kid.gatekeeper

/**
 * Age tiers for Aegis-Kid OS (India Edition).
 *
 * The tier is bound to the child profile at Device Owner provisioning time and
 * is the single input (alongside the target URL / package id) that may ever
 * leave the device in an Ed25519 unblock challenge. No name, age in years,
 * photo, or any other child PII is attached to it.
 *
 * Thresholds are *classifier-confidence* cut-offs, not ages: a score at or
 * above [blockThreshold] for a blocked category is a BLOCK; a score at or
 * above [escalateThreshold] for an escalated category is an ESCALATE (no
 * local override - the request goes to the Cloud AI Safety Adjudicator /
 * Human Support queue, see Deliverable 5).
 */
enum class AgeTier(
    val minAge: Int,
    val maxAge: Int,
    /** Classifier confidence at/above which a blocked-category hit is a BLOCK. */
    val blockThreshold: Float,
    /** Classifier confidence at/above which an escalated-category hit is an ESCALATE. */
    val escalateThreshold: Float,
    /** Minimum gap between low-power OCR screen-guard samples. */
    val ocrSampleIntervalMs: Long,
    /** Max characters of visible page / OCR text handed to the classifier in one call. */
    val maxClassifiedChars: Int,
    val displayName: String,
) {
    AGE_5_8(
        minAge = 5,
        maxAge = 8,
        blockThreshold = 0.55f,
        escalateThreshold = 0.35f,
        ocrSampleIntervalMs = 45_000L,
        maxClassifiedChars = 2_000,
        displayName = "5-8",
    ),
    AGE_9_12(
        minAge = 9,
        maxAge = 12,
        blockThreshold = 0.60f,
        escalateThreshold = 0.40f,
        ocrSampleIntervalMs = 60_000L,
        maxClassifiedChars = 3_000,
        displayName = "9-12",
    ),
    AGE_13_15(
        minAge = 13,
        maxAge = 15,
        blockThreshold = 0.65f,
        escalateThreshold = 0.45f,
        ocrSampleIntervalMs = 90_000L,
        maxClassifiedChars = 4_000,
        displayName = "13-15",
    ),
    AGE_16_17(
        minAge = 16,
        maxAge = 17,
        blockThreshold = 0.70f,
        escalateThreshold = 0.50f,
        ocrSampleIntervalMs = 120_000L,
        maxClassifiedChars = 4_000,
        displayName = "16-17",
    );

    companion object {
        /** Policy / rubric schema version. Bump when [AgeRubric] or age_rubrics.json changes. */
        const val POLICY_VERSION: Int = 1

        /** Resolve a tier from an age in years. Ages outside 5-17 clamp to the nearest tier. */
        fun fromAge(ageYears: Int): AgeTier = when {
            ageYears <= 8 -> AGE_5_8
            ageYears <= 12 -> AGE_9_12
            ageYears <= 15 -> AGE_13_15
            else -> AGE_16_17
        }

        fun fromDisplayName(name: String): AgeTier =
            entries.firstOrNull { it.displayName == name } ?: AGE_9_12
    }
}
