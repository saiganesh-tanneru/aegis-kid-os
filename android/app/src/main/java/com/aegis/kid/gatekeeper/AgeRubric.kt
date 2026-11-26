package com.aegis.kid.gatekeeper

import android.content.res.AssetManager
import org.json.JSONObject

/**
 * Content categories the classifier can return. The ordinal of each entry is
 * the model output index (see assets/models/README.md): the .tflite model
 * MUST emit one score per entry, in this exact order. Adding a category is a
 * model + rubric + JSON breaking change - bump [AgeTier.POLICY_VERSION].
 */
enum class RiskCategory {
    EDUCATIONAL,
    KIDS_ENTERTAINMENT,
    GENERAL_ENTERTAINMENT,
    SOCIAL_MEDIA,
    MESSAGING,
    VIDEO_STREAMING,
    GAMING,
    NEWS,
    SEARCH_ENGINE,
    SHOPPING,
    FINANCIAL,
    ADULT_SEXUAL,
    VIOLENCE,
    SELF_HARM,
    SUBSTANCE_USE,
    GAMBLING,
    HATE_EXTREMISM,
    WEAPONS,
    PROFANITY,
    DATING,
    ANONYMOUS_CHAT,
    PERSONAL_DATA_REQUEST,
    UNKNOWN,
}

/** Per-tier policy: which categories block outright, which escalate, which pass. */
data class TierRubric(
    val tier: AgeTier,
    val blocked: Set<RiskCategory>,
    val escalated: Set<RiskCategory>,
    val allowed: Set<RiskCategory>,
) {
    fun decisionFor(category: RiskCategory, confidence: Float): Decision = when {
        category in blocked && confidence >= tier.blockThreshold -> Decision.BLOCK
        category in escalated && confidence >= tier.escalateThreshold -> Decision.ESCALATE
        category in blocked && confidence >= tier.escalateThreshold -> Decision.ESCALATE
        else -> Decision.ALLOW
    }
}

/**
 * Age-tier rubrics. The hard-coded table below is the fallback of last
 * resort; at startup the DPC loads `assets/age_rubrics.json` (same schema)
 * and [loadFromAssets] overrides it when the JSON parses cleanly. If the
 * JSON is missing or corrupt, the hard-coded table is used and the failure
 * is counted - never crash, never fail open.
 *
 * Design rule: for ages 5-8 the default is deny. Anything that is not
 * recognisably educational or kids-entertainment escalates instead of
 * being silently allowed.
 */
object AgeRubric {

    private val hardCoded: Map<AgeTier, TierRubric> = mapOf(
        AgeTier.AGE_5_8 to TierRubric(
            tier = AgeTier.AGE_5_8,
            blocked = setOf(
                RiskCategory.SOCIAL_MEDIA, RiskCategory.MESSAGING,
                RiskCategory.VIDEO_STREAMING, RiskCategory.GAMING,
                RiskCategory.NEWS, RiskCategory.SEARCH_ENGINE,
                RiskCategory.SHOPPING, RiskCategory.FINANCIAL,
                RiskCategory.ADULT_SEXUAL, RiskCategory.VIOLENCE,
                RiskCategory.SELF_HARM, RiskCategory.SUBSTANCE_USE,
                RiskCategory.GAMBLING, RiskCategory.HATE_EXTREMISM,
                RiskCategory.WEAPONS, RiskCategory.PROFANITY,
                RiskCategory.DATING, RiskCategory.ANONYMOUS_CHAT,
                RiskCategory.PERSONAL_DATA_REQUEST,
            ),
            escalated = setOf(
                RiskCategory.GENERAL_ENTERTAINMENT, RiskCategory.UNKNOWN,
            ),
            allowed = setOf(RiskCategory.EDUCATIONAL, RiskCategory.KIDS_ENTERTAINMENT),
        ),
        AgeTier.AGE_9_12 to TierRubric(
            tier = AgeTier.AGE_9_12,
            blocked = setOf(
                RiskCategory.SOCIAL_MEDIA, RiskCategory.MESSAGING,
                RiskCategory.SHOPPING, RiskCategory.FINANCIAL,
                RiskCategory.ADULT_SEXUAL, RiskCategory.VIOLENCE,
                RiskCategory.SELF_HARM, RiskCategory.SUBSTANCE_USE,
                RiskCategory.GAMBLING, RiskCategory.HATE_EXTREMISM,
                RiskCategory.WEAPONS, RiskCategory.PROFANITY,
                RiskCategory.DATING, RiskCategory.ANONYMOUS_CHAT,
                RiskCategory.PERSONAL_DATA_REQUEST,
            ),
            escalated = setOf(
                RiskCategory.GENERAL_ENTERTAINMENT, RiskCategory.VIDEO_STREAMING,
                RiskCategory.GAMING, RiskCategory.NEWS, RiskCategory.SEARCH_ENGINE,
                RiskCategory.UNKNOWN,
            ),
            allowed = setOf(RiskCategory.EDUCATIONAL, RiskCategory.KIDS_ENTERTAINMENT),
        ),
        AgeTier.AGE_13_15 to TierRubric(
            tier = AgeTier.AGE_13_15,
            blocked = setOf(
                RiskCategory.ADULT_SEXUAL, RiskCategory.SELF_HARM,
                RiskCategory.GAMBLING, RiskCategory.HATE_EXTREMISM,
                RiskCategory.WEAPONS, RiskCategory.DATING,
                RiskCategory.ANONYMOUS_CHAT, RiskCategory.FINANCIAL,
                RiskCategory.PERSONAL_DATA_REQUEST,
            ),
            escalated = setOf(
                RiskCategory.SOCIAL_MEDIA, RiskCategory.MESSAGING,
                RiskCategory.VIOLENCE, RiskCategory.SUBSTANCE_USE,
                RiskCategory.PROFANITY, RiskCategory.SHOPPING,
                RiskCategory.GENERAL_ENTERTAINMENT, RiskCategory.VIDEO_STREAMING,
                RiskCategory.GAMING, RiskCategory.NEWS, RiskCategory.SEARCH_ENGINE,
            ),
            allowed = setOf(RiskCategory.EDUCATIONAL, RiskCategory.KIDS_ENTERTAINMENT),
        ),
        AgeTier.AGE_16_17 to TierRubric(
            tier = AgeTier.AGE_16_17,
            blocked = setOf(
                RiskCategory.ADULT_SEXUAL, RiskCategory.SELF_HARM,
                RiskCategory.GAMBLING, RiskCategory.HATE_EXTREMISM,
                RiskCategory.WEAPONS, RiskCategory.DATING,
                RiskCategory.ANONYMOUS_CHAT, RiskCategory.FINANCIAL,
                RiskCategory.PERSONAL_DATA_REQUEST,
            ),
            escalated = setOf(
                RiskCategory.SOCIAL_MEDIA, RiskCategory.MESSAGING,
                RiskCategory.VIOLENCE, RiskCategory.SUBSTANCE_USE,
                RiskCategory.PROFANITY, RiskCategory.SHOPPING,
            ),
            allowed = setOf(
                RiskCategory.EDUCATIONAL, RiskCategory.KIDS_ENTERTAINMENT,
                RiskCategory.GENERAL_ENTERTAINMENT, RiskCategory.VIDEO_STREAMING,
                RiskCategory.GAMING, RiskCategory.NEWS, RiskCategory.SEARCH_ENGINE,
            ),
        ),
    )

    @Volatile
    private var active: Map<AgeTier, TierRubric> = hardCoded

    fun rubricFor(tier: AgeTier): TierRubric = active[tier] ?: hardCoded.getValue(tier)

    /** Map a (category, confidence) pair to a decision under a tier's rubric. */
    fun decide(category: RiskCategory, confidence: Float, tier: AgeTier): Decision =
        rubricFor(tier).decisionFor(category, confidence)

    /**
     * Load `age_rubrics.json` from assets. Returns true on success.
     * On any failure the hard-coded table stays active (fail closed: the
     * hard-coded table is strictly more restrictive than the JSON for 5-8).
     * The JSON is parsed into sets of category names; unknown category
     * names are ignored rather than crashing the load.
     */
    fun loadFromAssets(assets: AssetManager): Boolean {
        return try {
            val jsonText = assets.open("age_rubrics.json").bufferedReader(Charsets.UTF_8).use { it.readText() }
            val root = JSONObject(jsonText)
            val parsed = mutableMapOf<AgeTier, TierRubric>()
            val tiers = root.getJSONObject("tiers")
            for (tier in AgeTier.entries) {
                if (!tiers.has(tier.displayName)) continue
                val node = tiers.getJSONObject(tier.displayName)
                parsed[tier] = TierRubric(
                    tier = tier,
                    blocked = parseCategories(node.optJSONArray("blocked")),
                    escalated = parseCategories(node.optJSONArray("escalated")),
                    allowed = parseCategories(node.optJSONArray("allowed")),
                )
            }
            if (parsed.size == AgeTier.entries.size) {
                active = parsed
                true
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun parseCategories(array: org.json.JSONArray?): Set<RiskCategory> {
        if (array == null) return emptySet()
        val out = mutableSetOf<RiskCategory>()
        for (i in 0 until array.length()) {
            runCatching { RiskCategory.valueOf(array.getString(i)) }.onSuccess { out += it }
        }
        return out
    }
}
