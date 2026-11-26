package com.aegis.kid.gatekeeper

import android.content.pm.Signature
import java.net.IDN
import java.security.MessageDigest
import java.util.Locale

/**
 * Signature-verified bypass for Indian EdTech apps and their CDN domains.
 *
 * Rationale: deep inspection breaks DRM video streams (Widevine) and burns
 * battery on 3-4 GB RAM tablets. Traffic that is *cryptographically* proven
 * to come from a signature-verified EdTech app, to that app's own CDN
 * domains, bypasses the LiteRT classifier - but it NEVER bypasses the
 * domain allowlist. Any other host requested by the same app still goes
 * through the classifier / WebView containment.
 *
 * Verification is two-factor:
 *  1. Package name must be in [EDTECH_APPS], AND
 *  2. The APK signing certificate SHA-256 must equal the pinned value.
 * A repackaged / sideloaded clone with the same package name but a
 * different signature fails check 2 and gets no bypass.
 *
 * SECURITY NOTE: the `certSha256Hex` values below are PLACEHOLDERS
 * ("REPLACE_WITH_REAL_SHA256"). They must be replaced with the real
 * Play-Store signing-certificate fingerprints, captured from the Play
 * Console / `apksigner verify --print-certs`, before any production
 * build. While a placeholder is present, [verifySignature] returns
 * false (fail closed) - the bypass is inert until pinned properly.
 * Package names below are best-effort and must be re-verified against
 * the live Play Store listing at integration time.
 */
object AllowlistBypass {

    data class EdTechApp(
        val packageName: String,
        val displayName: String,
        /** Lower-case hex SHA-256 of the APK signing certificate. Placeholder until pinned. */
        val certSha256Hex: String,
        /** Exact hosts + parent domains this app may reach without classification. */
        val allowedHosts: Set<String>,
    )

    const val PLACEHOLDER_CERT_HASH: String = "REPLACE_WITH_REAL_SHA256"

    val EDTECH_APPS: List<EdTechApp> = listOf(
        EdTechApp(
            packageName = "org.khanacademy.android",
            displayName = "Khan Academy",
            certSha256Hex = PLACEHOLDER_CERT_HASH,
            allowedHosts = setOf("khanacademy.org", "ka-perseus-images.s3.amazonaws.com", "cdn.kastatic.org", "fastly.kastatic.org"),
        ),
        EdTechApp(
            packageName = "com.google.android.apps.youtube.kids",
            displayName = "YouTube Kids",
            certSha256Hex = PLACEHOLDER_CERT_HASH,
            allowedHosts = setOf("kids.youtube.com", "youtube-nocookie.com", "yt3.ggpht.com", "i.ytimg.com", "googlevideo.com"),
        ),
        EdTechApp(
            packageName = "com.byjus.thelearningapp",
            displayName = "BYJU'S - The Learning App",
            certSha256Hex = PLACEHOLDER_CERT_HASH,
            allowedHosts = setOf("byjus.com", "cdn.byjus.com", "media.byjus.com", "learn.byjus.com"),
        ),
        EdTechApp(
            packageName = "com.unacademy",
            displayName = "Unacademy",
            certSha256Hex = PLACEHOLDER_CERT_HASH,
            allowedHosts = setOf("unacademy.com", "static.uacdn.net", "edge.uacdn.net"),
        ),
        EdTechApp(
            packageName = "com.pw.live",
            displayName = "Physics Wallah (PW)",
            certSha256Hex = PLACEHOLDER_CERT_HASH,
            allowedHosts = setOf("pw.live", "physicswallah.live", "d2bps9p1kiy4ka.cloudfront.net", "cdn.pw.live"),
        ),
        EdTechApp(
            packageName = "org.diksha.app",
            displayName = "DIKSHA (NCERT)",
            certSha256Hex = PLACEHOLDER_CERT_HASH,
            allowedHosts = setOf("diksha.gov.in", "ncert.nic.in", "sunbird.org", "diksha.gov.in"),
        ),
        EdTechApp(
            packageName = "com.aakashdigital.app",
            displayName = "Aakash Digital",
            certSha256Hex = PLACEHOLDER_CERT_HASH,
            allowedHosts = setOf("aakash.ac.in", "cdn.aakash.ac.in"),
        ),
    )

    /** All CDN / content hosts any allowlisted app may reach. Domain-level bypass only. */
    val ALLOWED_CDN_DOMAINS: Set<String> = EDTECH_APPS
        .flatMap { it.allowedHosts }
        .toSet() + setOf(
        "ncert.nic.in", "epathshala.nic.in", "swayam.gov.in", "ndl.iitkgp.ac.in",
    )

    /** Hosts that are always blocked, even for allowlisted apps (escape routes). */
    val BLOCKED_HOSTS: Set<String> = setOf(
        "google.com", "www.google.com", "bing.com", "www.bing.com",
        "duckduckgo.com", "search.yahoo.com", "yahoo.com", "brave.com",
        "chatgpt.com", "chat.openai.com", "gemini.google.com",
    )

    /** UPI / payment hosts and apps: never reachable from the child profile. */
    val FINANCIAL_HOSTS: Set<String> = setOf(
        "pay.google.com", "paytm.com", "phonepe.com", "bhimupi.org.in",
        "upi.npci.org.in", "razorpay.com", "payu.in",
    )

    val BLOCKED_SCHEMES: Set<String> = setOf(
        "file", "intent", "market", "content", "javascript", "data", "blob",
    )

    /** Normalise a host for comparison: lower-case, strip trailing dot, IDN to ASCII. */
    fun normalizeHost(rawHost: String?): String? {
        if (rawHost.isNullOrBlank()) return null
        return try {
            IDN.toASCII(rawHost.trim().lowercase(Locale.ROOT).trimEnd('.'))
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** Exact host or any sub-domain of an allowlisted host. */
    fun isAllowlistedHost(rawHost: String?): Boolean {
        val host = normalizeHost(rawHost) ?: return false
        return ALLOWED_CDN_DOMAINS.any { allowed -> host == allowed || host.endsWith(".$allowed") }
    }

    fun isBlockedHost(rawHost: String?): Boolean {
        val host = normalizeHost(rawHost) ?: return false
        return (BLOCKED_HOSTS + FINANCIAL_HOSTS).any { blocked -> host == blocked || host.endsWith(".$blocked") }
    }

    fun isFinancialHost(rawHost: String?): Boolean {
        val host = normalizeHost(rawHost) ?: return false
        return FINANCIAL_HOSTS.any { blocked -> host == blocked || host.endsWith(".$blocked") }
    }

    /**
     * Verify an APK signature against the pinned certificate hash.
     * Returns false for placeholder hashes, unknown packages, empty
     * signatures, or any mismatch. Fail closed, always.
     */
    fun verifySignature(packageName: String, signatures: Array<Signature>?): Boolean {
        if (signatures.isNullOrEmpty()) return false
        val app = EDTECH_APPS.firstOrNull { it.packageName == packageName } ?: return false
        if (app.certSha256Hex == PLACEHOLDER_CERT_HASH) return false
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            signatures.any { signature ->
                val hash = digest.digest(signature.toByteArray())
                    .joinToString("") { byte -> "%02x".format(byte) }
                // Constant-time-ish comparison; hashes are public fingerprints, not secrets.
                hash.equals(app.certSha256Hex.lowercase(Locale.ROOT), ignoreCase = true)
            }
        } catch (_: Exception) {
            false
        }
    }

    sealed interface BypassDecision {
        /** App + signature + host all verified: skip the classifier for this request. */
        data object Bypass : BypassDecision
        /** Not an allowlisted app/host: run the normal classifier path. */
        data object NoBypass : BypassDecision
        /** Allowlisted app asking for a non-allowlisted host: block the escape, do not classify. */
        data object BlockEscape : BypassDecision
    }

    /**
     * Decide a request from an app. [host] is the request host (already
     * normalised inside). If the app is allowlisted but the host is not,
     * the request is an escape attempt and is blocked outright.
     */
    fun bypassForApp(packageName: String, signatures: Array<Signature>?, host: String?): BypassDecision {
        val app = EDTECH_APPS.firstOrNull { it.packageName == packageName } ?: return BypassDecision.NoBypass
        if (!verifySignature(packageName, signatures)) return BypassDecision.NoBypass
        val normalized = normalizeHost(host) ?: return BypassDecision.BlockEscape
        val hostOk = app.allowedHosts.any { allowed -> normalized == allowed || normalized.endsWith(".$allowed") }
        return if (hostOk) BypassDecision.Bypass else BypassDecision.BlockEscape
    }

    /** WebView-level check: is this host a known EdTech CDN (classifier bypass, domain check only)? */
    fun isBypassHost(rawHost: String?): Boolean = isAllowlistedHost(rawHost)
}
