package com.aegis.kid.gatekeeper

import android.net.Uri
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import java.io.ByteArrayInputStream
import java.util.concurrent.atomic.AtomicLong

/**
 * URL / request interceptor for the gatekeeper WebView.
 *
 * Runs BEFORE any navigation or sub-resource load:
 *  - blocked schemes (`file://`, `intent://`, `market://`, `javascript:`,
 *    `data:`, `blob:`, `content://`) are rejected outright - these are the
 *    classic WebView escape routes to the Play Store, other apps, or local
 *    files;
 *  - signature-verified EdTech CDN hosts bypass the classifier (DRM /
 *    battery, see [AllowlistBypass]);
 *  - search engines, UPI / payment hosts, and any other non-allowlisted
 *    host are blocked without ever fetching the page;
 *  - everything else is allowed to navigate, but its visible text is
 *    classified after load by [GatekeeperWebView] - navigation is never
 *    the final word, content is.
 *
 * This class performs NO network I/O itself and logs no URLs or hosts.
 * Only counters leave this class.
 */
class WebViewInterceptor(
    private val classifier: SafetyClassifier,
    private val tierProvider: () -> AgeTier,
) {

    enum class InterceptDecision { ALLOW, BLOCK, ESCALATE }

    data class InterceptResult(
        val decision: InterceptDecision,
        val reasonCode: ReasonCode,
        val category: RiskCategory = RiskCategory.UNKNOWN,
    )

    val allowedRequests = AtomicLong(0)
    val blockedRequests = AtomicLong(0)
    val escalatedRequests = AtomicLong(0)

    // ------------------------------------------------------------------
    // Navigation-time evaluation
    // ------------------------------------------------------------------

    /** Evaluate a navigation URL. Never fetches the URL. */
    fun evaluateUrl(rawUrl: String): InterceptResult {
        val tier = tierProvider()
        val uri = runCatching { Uri.parse(rawUrl) }.getOrNull()
            ?: return block(ReasonCode.SCHEME_BLOCK)
        val scheme = uri.scheme?.lowercase().orEmpty()
        if (scheme.isBlank()) return block(ReasonCode.SCHEME_BLOCK)
        if (scheme in AllowlistBypass.BLOCKED_SCHEMES) return block(ReasonCode.SCHEME_BLOCK)
        if (scheme != "http" && scheme != "https") return block(ReasonCode.SCHEME_BLOCK)

        val host = uri.host ?: return block(ReasonCode.DOMAIN_NOT_ALLOWLISTED)

        // In-app escape to a search engine: the child must not be able to
        // pivot from an allowlisted page to open search.
        if (AllowlistBypass.isBlockedHost(host)) {
            return if (AllowlistBypass.isFinancialHost(host)) {
                block(ReasonCode.FINANCIAL_APP_BLOCK)
            } else {
                block(ReasonCode.SEARCH_ENGINE_BLOCK)
            }
        }

        // Signature-verified EdTech CDN: bypass the classifier, domain check only.
        if (AllowlistBypass.isBypassHost(host)) {
            allowedRequests.incrementAndGet()
            return InterceptResult(InterceptDecision.ALLOW, ReasonCode.ALLOWLISTED_DOMAIN)
        }

        // Host / path token check: catches obvious high-risk destinations
        // (e.g. a link whose path contains adult / gambling keywords)
        // without fetching anything.
        val tokens = tokenizeUri(uri)
        val tokenVerdict = classifier.classifyUrlTokens(tokens, tier)
        return when (tokenVerdict.decision) {
            Decision.ALLOW -> {
                allowedRequests.incrementAndGet()
                InterceptResult(InterceptDecision.ALLOW, ReasonCode.CLASSIFIER_ALLOW, tokenVerdict.category)
            }
            Decision.BLOCK -> block(ReasonCode.RULE_BLOCK, tokenVerdict.category)
            Decision.ESCALATE -> escalate(ReasonCode.RULE_ESCALATE, tokenVerdict.category)
        }
    }

    /**
     * Sub-resource interception. Returning a non-null [WebResourceResponse]
     * cancels the load. Returning null lets the WebView load it normally.
     * Only the host / scheme is inspected here - bodies are never read.
     */
    fun shouldInterceptRequest(request: WebResourceRequest): WebResourceResponse? {
        val url = request.url ?: return null
        val scheme = url.scheme?.lowercase().orEmpty()
        if (scheme in AllowlistBypass.BLOCKED_SCHEMES) {
            blockedRequests.incrementAndGet()
            return blockedResponse()
        }
        if (scheme != "http" && scheme != "https") return blockedResponse()
        val host = url.host ?: return blockedResponse()
        if (AllowlistBypass.isBlockedHost(host)) {
            blockedRequests.incrementAndGet()
            return blockedResponse()
        }
        // Allowlisted CDN sub-resources (images, video segments, fonts)
        // pass through untouched so DRM playback is not broken.
        return null
    }

    /** Called from WebViewClient.onLoadResource: host-only accounting, cannot cancel here. */
    fun onLoadResource(rawUrl: String) {
        val host = runCatching { Uri.parse(rawUrl).host }.getOrNull() ?: return
        if (AllowlistBypass.isBlockedHost(host)) blockedRequests.incrementAndGet()
    }

    /** A 403 empty response: the resource simply never loads. No content, no redirect. */
    fun blockedResponse(): WebResourceResponse {
        return WebResourceResponse(
            "text/plain",
            "UTF-8",
            403,
            "Blocked by Aegis-Kid OS",
            emptyMap(),
            ByteArrayInputStream(ByteArray(0)),
        )
    }

    private fun block(reasonCode: ReasonCode, category: RiskCategory = RiskCategory.UNKNOWN): InterceptResult {
        blockedRequests.incrementAndGet()
        return InterceptResult(InterceptDecision.BLOCK, reasonCode, category)
    }

    private fun escalate(reasonCode: ReasonCode, category: RiskCategory = RiskCategory.UNKNOWN): InterceptResult {
        escalatedRequests.incrementAndGet()
        return InterceptResult(InterceptDecision.ESCALATE, reasonCode, category)
    }

    /**
     * Split a URI into classifier tokens: host labels + path segments,
     * split on non-letters. The full URL string is never retained - the
     * token list is a local and is discarded by the caller.
     */
    private fun tokenizeUri(uri: Uri): List<String> {
        val tokens = ArrayList<String>()
        uri.host?.split('.')?.let { tokens += it }
        uri.pathSegments.forEach { segment ->
            tokens += segment.split(Regex("[^\\p{L}0-9]+")).filter { it.isNotEmpty() }
        }
        uri.getQueryParameterNames().forEach { name ->
            tokens += name.split(Regex("[^\\p{L}0-9]+")).filter { it.isNotEmpty() }
        }
        return tokens
    }
}
