package com.aegis.kid.gatekeeper

import java.text.Normalizer
import java.util.Locale

/** Writing system detected in a sample of text. */
enum class DetectedScript {
    LATIN, DEVANAGARI, TELUGU, TAMIL, BENGALI, KANNADA, MALAYALAM, GUJARATI, GURMUKHI, OTHER, NONE,
}

/** Language / code-mix label. HINGLISH = Hindi in Latin script, often mixed with English. */
enum class Language {
    ENGLISH, HINDI_DEVANAGARI, HINGLISH, TELUGU, TAMIL, BENGALI, KANNADA,
    MALAYALAM, MARATHI, GUJARATI, PUNJABI, UNKNOWN, MIXED,
}

data class LanguageDetection(
    val primary: Language,
    /** Share of letters in each script, 0..1. */
    val scriptShares: Map<DetectedScript, Float>,
    val isHinglish: Boolean,
    val isMixed: Boolean,
    val confidence: Float,
)

/**
 * Multilingual detection for the gatekeeper: script identification by
 * Unicode block, Hinglish / Romanized-Hindi identification by keyword
 * density, and high-risk keyword matching per language and category.
 *
 * This is the rule-based safety net. It runs when the LiteRT model is
 * missing or OOM-killed, and it also runs *before* the model as a fast
 * pre-filter: an unambiguous high-risk keyword hit short-circuits to a
 * BLOCK without spending model inference time or battery.
 *
 * Keyword lists are starter lists, not exhaustive. They must be reviewed
 * and extended by native speakers per language before production; a word
 * that is harmless in one language can be a slur in another, so lists are
 * keyed per language and never applied cross-language.
 *
 * NOTE on the profanity / adult lists below: these words exist in this
 * file ONLY so the on-device filter can recognise them. They are never
 * logged, never displayed, and never leave the device.
 */
object HinglishDetector {

    // ------------------------------------------------------------------
    // Script detection: Unicode ranges (single source of truth).
    // ------------------------------------------------------------------

    fun scriptOf(ch: Char): DetectedScript = when (ch.code) {
        in 0x0900..0x097F -> DetectedScript.DEVANAGARI
        in 0x0C00..0x0C7F -> DetectedScript.TELUGU
        in 0x0B80..0x0BFF -> DetectedScript.TAMIL
        in 0x0980..0x09FF -> DetectedScript.BENGALI
        in 0x0C80..0x0CFF -> DetectedScript.KANNADA
        in 0x0D00..0x0D7F -> DetectedScript.MALAYALAM
        in 0x0A80..0x0AFF -> DetectedScript.GUJARATI
        in 0x0A00..0x0A7F -> DetectedScript.GURMUKHI
        in 0x0041..0x005A, in 0x0061..0x007A -> DetectedScript.LATIN
        else -> DetectedScript.OTHER
    }

    fun detectScriptShares(text: CharSequence): Map<DetectedScript, Float> {
        val counts = mutableMapOf<DetectedScript, Int>()
        var letters = 0
        for (ch in text) {
            if (!ch.isLetter()) continue
            letters++
            val script = scriptOf(ch)
            if (script != DetectedScript.OTHER) counts[script] = (counts[script] ?: 0) + 1
        }
        if (letters == 0) return mapOf(DetectedScript.NONE to 1f)
        return counts.mapValues { (_, count) -> count.toFloat() / letters }
    }

    // ------------------------------------------------------------------
    // Romanized-Hindi / Hinglish markers and regional-language markers.
    // Word lists are lower-cased, diacritic-free, and matched on whole
    // tokens (see [tokenize]) so "kya" does not fire inside "kyara".
    // ------------------------------------------------------------------

    /** Common Hinglish function / everyday words - high density => Hinglish, not English. */
    private val hinglishMarkers: Set<String> = setOf(
        "kya", "kyu", "kyun", "kaise", "kaisa", "kahan", "kab", "kaun", "mera", "meri", "mere",
        "tera", "teri", "tere", "uska", "uski", "hamara", "tumhara", "aapka", "mujhe", "tumhe",
        "nahi", "nahin", "matlab", "accha", "acha", "theek", "bahut", "bohot", "zyada", "thoda",
        "bhai", "behen", "yaar", "dost", "arre", "chal", "chalo", "dekho", "sunno", "bolo",
        "hai", "hain", "tha", "thi", "hoga", "karna", "karo", "jao", "aao", "khel", "padhai",
        "batao", "samajh", "pata", "abhi", "kal", "aaj", "phir", "bhi", "toh", "hi", "na",
    )

    private val teluguRomanMarkers: Set<String> = setOf(
        "ela", "unnaru", "bagunnava", "bagundi", "em", "chestunnav", "cheppu", "nenu", "nuvvu",
        "meeru", "akka", "anna", "chelli", "tammudu", "ra", "rey", "inka", "ipudu", "repu",
        "chala", "konchem", "telugu", "andhra", "telangana",
    )

    private val tamilRomanMarkers: Set<String> = setOf(
        "epdi", "eppadi", "enna", "enga", "eppo", "yaaru", "naan", "nee", "neenga", "amma",
        "appa", "akka", "anna", "thambi", "romba", "konjam", "iniki", "naalaiku", "tamil",
        "super", "semma", "da", "di", "paaru", "sollu",
    )

    /** Identify the dominant language / code-mix of a sample. Pure heuristic - the LiteRT model is authoritative. */
    fun detect(text: CharSequence): LanguageDetection {
        val shares = detectScriptShares(text)
        val dominant = shares.maxByOrNull { it.value }?.key ?: DetectedScript.NONE
        val dominantShare = shares[dominant] ?: 0f
        val tokens = tokenize(text)
        if (tokens.isEmpty()) {
            return LanguageDetection(Language.UNKNOWN, shares, isHinglish = false, isMixed = false, confidence = 0f)
        }
        val hinglishHits = tokens.count { it in hinglishMarkers }
        val teluguHits = tokens.count { it in teluguRomanMarkers }
        val tamilHits = tokens.count { it in tamilRomanMarkers }
        val total = tokens.size.toFloat()

        val primary: Language
        val confidence: Float
        when {
            dominant == DetectedScript.DEVANAGARI -> { primary = Language.HINDI_DEVANAGARI; confidence = dominantShare }
            dominant == DetectedScript.TELUGU -> { primary = Language.TELUGU; confidence = dominantShare }
            dominant == DetectedScript.TAMIL -> { primary = Language.TAMIL; confidence = dominantShare }
            dominant == DetectedScript.BENGALI -> { primary = Language.BENGALI; confidence = dominantShare }
            dominant == DetectedScript.KANNADA -> { primary = Language.KANNADA; confidence = dominantShare }
            dominant == DetectedScript.MALAYALAM -> { primary = Language.MALAYALAM; confidence = dominantShare }
            dominant == DetectedScript.GUJARATI -> { primary = Language.GUJARATI; confidence = dominantShare }
            dominant == DetectedScript.GURMUKHI -> { primary = Language.PUNJABI; confidence = dominantShare }
            hinglishHits / total >= 0.20f -> { primary = Language.HINGLISH; confidence = hinglishHits / total }
            teluguHits / total >= 0.20f -> { primary = Language.TELUGU; confidence = teluguHits / total }
            tamilHits / total >= 0.20f -> { primary = Language.TAMIL; confidence = tamilHits / total }
            dominant == DetectedScript.LATIN -> { primary = Language.ENGLISH; confidence = dominantShare }
            else -> { primary = Language.UNKNOWN; confidence = 0f }
        }
        val secondShare = shares.entries.sortedByDescending { it.value }.drop(1).firstOrNull()?.value ?: 0f
        val isMixed = secondShare >= 0.15f || (hinglishHits > 0 && primary == Language.ENGLISH)
        return LanguageDetection(
            primary = if (isMixed && primary != Language.HINGLISH) Language.MIXED else primary,
            scriptShares = shares,
            isHinglish = primary == Language.HINGLISH || hinglishHits / total >= 0.10f,
            isMixed = isMixed,
            confidence = confidence.coerceIn(0f, 1f),
        )
    }

    // ------------------------------------------------------------------
    // High-risk keyword lists, keyed by (category, language).
    // Scores: a single strong hit scores 0.85, two distinct hits 0.95.
    // These lists feed SafetyClassifier's rule-based fallback AND the
    // WebView pre-filter. They are deliberately NOT exhaustive for adult
    // content: the LiteRT model is the primary detector there.
    // ------------------------------------------------------------------

    // English (applies to Latin-script English text only).
    private val englishKeywords: Map<RiskCategory, Set<String>> = mapOf(
        RiskCategory.ADULT_SEXUAL to setOf(
            "porn", "pornhub", "xvideos", "xxx", "nude", "naked", "sex video", "onlyfans",
            "escort", "cam girl", "erotic",
        ),
        RiskCategory.VIOLENCE to setOf(
            "how to kill", "murder", "shoot someone", "make a bomb", "stab", "beheading",
            "gore video", "torture",
        ),
        RiskCategory.SELF_HARM to setOf(
            "how to die", "kill myself", "suicide", "self harm", "cut myself", "end my life",
            "hang myself", "overdose",
        ),
        RiskCategory.SUBSTANCE_USE to setOf(
            "buy drugs", "buy cocaine", "buy weed online", "meth", "heroin for sale",
            "how to make drugs", "vape for kids",
        ),
        RiskCategory.GAMBLING to setOf(
            "online casino", "betting app", "satta", "teen patti cash", "win real money",
            "betting tips", "rummy cash",
        ),
        RiskCategory.HATE_EXTREMISM to setOf(
            "kill all", "hate speech", "join isis", "terrorist attack plan",
        ),
        RiskCategory.WEAPONS to setOf(
            "buy a gun", "buy pistol", "how to make a gun", "buy bullets", "3d print gun",
        ),
        RiskCategory.PROFANITY to setOf(
            "fuck", "shit", "bitch", "bastard", "dick", "pussy", "motherfucker",
        ),
        RiskCategory.DATING to setOf(
            "dating app", "meet singles near me", "find a girlfriend online", "tinder",
        ),
        RiskCategory.ANONYMOUS_CHAT to setOf(
            "omegle", "anonymous chat", "chat with strangers", "random video chat",
        ),
        RiskCategory.FINANCIAL to setOf(
            "upi payment", "send money", "enter upi pin", "share otp", "bank otp",
        ),
        RiskCategory.PERSONAL_DATA_REQUEST to setOf(
            "enter your otp", "share your otp", "send your password", "enter aadhaar number",
            "share your location", "upload your photo",
        ),
    )

    // Hindi in Devanagari script.
    private val hindiDevanagariKeywords: Map<RiskCategory, Set<String>> = mapOf(
        RiskCategory.ADULT_SEXUAL to setOf("अश्लील", "सेक्स", "पोर्न", "नंगी", "नंगा", "बलात्कार"),
        RiskCategory.VIOLENCE to setOf("हिंसा", "हत्या", "मार डालो", "चाकू से मार", "बम बनाना"),
        RiskCategory.SELF_HARM to setOf("आत्महत्या", "खुद को मार", "मरना चाहता", "मरना चाहती"),
        RiskCategory.SUBSTANCE_USE to setOf("नशा", "शराब", "ड्रग्स", "गांजा", "अफीम", "चरस"),
        RiskCategory.GAMBLING to setOf("जुआ", "सट्टा", "बेटिंग"),
        RiskCategory.PROFANITY to setOf("चूतिया", "बकचोद", "मादरचोद", "बहनचोद", "हरामी", "कमीना", "साला"),
        RiskCategory.DATING to setOf("डेटिंग", "गर्लफ्रेंड बनाओ"),
        RiskCategory.FINANCIAL to setOf("ओटीपी बताओ", "यूपीआई पिन", "पैसे भेजो"),
    )

    // Hinglish: Hindi in Latin script. Same semantics as Devanagari, different spelling.
    // Spelling variants are handled by [normalizeRomanized] (repeated-letter collapse).
    private val hinglishKeywords: Map<RiskCategory, Set<String>> = mapOf(
        RiskCategory.ADULT_SEXUAL to setOf(
            "ashleel", "sex", "porn", "nangi", "nanga", "blue film", "gandi video",
        ),
        RiskCategory.VIOLENCE to setOf(
            "hinsa", "hatya", "maar dalo", "chaku se maar", "bomb banana",
        ),
        RiskCategory.SELF_HARM to setOf(
            "aatmahatya", "aatmahathya", "khud ko maar", "marna chahta", "marna chahti",
            "suicide karna",
        ),
        RiskCategory.SUBSTANCE_USE to setOf(
            "nasha", "sharaab", "sharabi", "drugs", "ganja", "charas", "gutka",
        ),
        RiskCategory.GAMBLING to setOf("jua", "satta", "betting", "teen patti"),
        RiskCategory.PROFANITY to setOf(
            "chutiya", "bakchod", "madarchod", "behenchod", "bhosdike", "harami",
            "kamina", "saala", "kutta", "randi",
        ),
        RiskCategory.DATING to setOf("dating", "girlfriend banao", "boyfriend banao"),
        RiskCategory.FINANCIAL to setOf("otp batao", "upi pin", "paise bhejo"),
        RiskCategory.ANONYMOUS_CHAT to setOf("omegle", "strangers se chat"),
    )

    // Telugu: script + Romanized forms. Starter list - extend with native review.
    private val teluguKeywords: Map<RiskCategory, Set<String>> = mapOf(
        RiskCategory.ADULT_SEXUAL to setOf("అశ్లీల", "సెక్స్", "పోర్న్", "ashleel", "sex"),
        RiskCategory.VIOLENCE to setOf("హింస", "చంపు", "హత్య", "himsa", "champu"),
        RiskCategory.SELF_HARM to setOf("ఆత్మహత్య", "aatmahatya", "suicide"),
        RiskCategory.SUBSTANCE_USE to setOf("మద్యం", "గంజాయి", "nasha", "ganja"),
        RiskCategory.GAMBLING to setOf("జూదం", "satta", "betting"),
        RiskCategory.PROFANITY to setOf("lanja", "kodaka", "pichi"),
    )

    // Tamil: script + Romanized forms. Starter list - extend with native review.
    private val tamilKeywords: Map<RiskCategory, Set<String>> = mapOf(
        RiskCategory.ADULT_SEXUAL to setOf("ஆபாசம்", "செக்ஸ்", "போர்ன்", "ashleel", "sex"),
        RiskCategory.VIOLENCE to setOf("வன்முறை", "கொல்", "கொலை", "vanmurai", "kollu"),
        RiskCategory.SELF_HARM to setOf("தற்கொலை", "thatkolai", "suicide"),
        RiskCategory.SUBSTANCE_USE to setOf("மது", "கஞ்சா", "ganja", "nasha"),
        RiskCategory.GAMBLING to setOf("சூதாட்டம்", "satta", "betting"),
        RiskCategory.PROFANITY to setOf("naaye", "loosu", "poda"),
    )

    /** Pick the keyword table for a detected language. Latin-script Indian languages share the Hinglish table. */
    fun keywordsFor(language: Language): Map<RiskCategory, Set<String>> = when (language) {
        Language.HINDI_DEVANAGARI -> hindiDevanagariKeywords
        Language.HINGLISH, Language.MIXED -> mergeKeywordTables(englishKeywords, hinglishKeywords)
        Language.TELUGU -> mergeKeywordTables(englishKeywords, teluguKeywords)
        Language.TAMIL -> mergeKeywordTables(englishKeywords, tamilKeywords)
        Language.ENGLISH -> englishKeywords
        else -> englishKeywords
    }

    private fun mergeKeywordTables(
        a: Map<RiskCategory, Set<String>>,
        b: Map<RiskCategory, Set<String>>,
    ): Map<RiskCategory, Set<String>> {
        val out = mutableMapOf<RiskCategory, MutableSet<String>>()
        for ((category, words) in a) out.getOrPut(category) { mutableSetOf() } += words
        for ((category, words) in b) out.getOrPut(category) { mutableSetOf() } += words
        return out
    }

    /**
     * Match high-risk keywords in [text]. Returns category -> score (0.85 for
     * one distinct hit, 0.95 for two or more). Only the *scores* are returned;
     * matched words are never returned, logged, or stored.
     */
    fun matchRiskCategories(text: CharSequence): Map<RiskCategory, Float> {
        if (text.isBlank()) return emptyMap()
        val detection = detect(text)
        val table = keywordsFor(detection.primary)
        val normalized = normalizeForMatching(text, detection.primary)
        val tokens = tokenize(normalized).toSet()
        val out = mutableMapOf<RiskCategory, Float>()
        for ((category, keywords) in table) {
            var hits = 0
            for (keyword in keywords) {
                val hit = if (' ' in keyword) {
                    " $normalized ".contains(" ${normalizeForMatching(keyword, detection.primary)} ")
                } else {
                    keyword in tokens
                }
                if (hit) hits++
            }
            if (hits == 1) out[category] = 0.85f
            if (hits >= 2) out[category] = 0.95f
        }
        return out
    }

    /** Lower-case + NFKC + collapse repeated Latin letters ("kyaaa" -> "kyaa" -> "kya"). */
    fun normalizeRomanized(text: CharSequence): String {
        val lower = text.toString().lowercase(Locale.ROOT)
        val folded = Normalizer.normalize(lower, Normalizer.Form.NFKC)
        val collapsed = StringBuilder(folded.length)
        var prev = '\u0000'
        var run = 0
        for (ch in folded) {
            if (ch == prev && ch in 'a'..'z') {
                run++
                if (run > 2) continue
            } else {
                run = 1
            }
            collapsed.append(ch)
            prev = ch
        }
        return collapsed.toString()
    }

    private fun normalizeForMatching(text: CharSequence, language: Language): String {
        val base = text.toString().lowercase(Locale.ROOT)
        return if (language == Language.HINGLISH || language == Language.MIXED ||
            language == Language.TELUGU || language == Language.TAMIL ||
            language == Language.ENGLISH
        ) {
            normalizeRomanized(base)
        } else {
            Normalizer.normalize(base, Normalizer.Form.NFKC)
        }
    }

    /** Split into word tokens on anything that is not a letter. Works for Latin and Indic scripts. */
    fun tokenize(text: CharSequence): List<String> {
        val out = ArrayList<String>()
        val current = StringBuilder()
        for (ch in text) {
            if (ch.isLetter()) {
                current.append(ch.lowercaseChar())
            } else if (current.isNotEmpty()) {
                out.add(current.toString())
                current.clear()
            }
        }
        if (current.isNotEmpty()) out.add(current.toString())
        return out
    }
}
