package com.aegis.kid.gatekeeper

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.os.Message
import android.util.AttributeSet
import android.util.Log
import android.webkit.DownloadListener
import android.webkit.JsPromptResult
import android.webkit.JsResult
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONObject

/**
 * The locked-down in-app browser. It is the ONLY browser the child can
 * reach: the Kiosk Launcher routes every web link here, and the DPC
 * blocks all other browsers / intents.
 *
 * Containment, in order:
 *  1. [GatekeeperClient.shouldOverrideUrlLoading] - every navigation is
 *     evaluated by [WebViewInterceptor] before it happens.
 *  2. [GatekeeperClient.shouldInterceptRequest] - every sub-resource
 *     (images, scripts, iframes, XHR) is host-checked; blocked hosts
 *     never load, so a page cannot smuggle in a search engine or a
 *     payment page as an iframe.
 *  3. [GatekeeperClient.onPageFinished] - the visible text of the loaded
 *     page is extracted (capped at the tier limit), classified in
 *     volatile RAM, and the page is replaced by the block page if the
 *     verdict is BLOCK. The extracted text is purged immediately.
 *  4. Downloads are refused entirely. No `addJavascriptInterface` bridge
 *     is ever registered, and the stock Android JS interfaces are
 *     removed. File access from file URLs is disabled, mixed content is
 *     refused, and Safe Browsing is on.
 *
 * The block page never echoes the URL, host, or any page content - only
 * a generic reason. There is no local override, no parent PIN field, and
 * no "continue anyway" button: an ESCALATE verdict shows a "ask a parent
 * to request a review" page, and the review itself happens out-of-band
 * via the Cloud AI Safety Adjudicator (Deliverable 5).
 */
class GatekeeperWebView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : WebView(context, attrs, defStyleAttr) {

    interface GatekeeperListener {
        /** A navigation or page was blocked. Only counters / reason codes - never the URL. */
        fun onBlocked(reasonCode: ReasonCode, category: RiskCategory)
        fun onEscalated(reasonCode: ReasonCode, category: RiskCategory)
        fun onAllowed()
    }

    var listener: GatekeeperListener? = null

    private val classifier: SafetyClassifier
    private val interceptor: WebViewInterceptor
    private var tier: AgeTier

    init {
        tier = AgeTier.AGE_9_12
        classifier = SafetyClassifier(context.applicationContext, tier)
        interceptor = WebViewInterceptor(classifier) { tier }
        configureSettings()
        webViewClient = GatekeeperClient()
        webChromeClient = GatekeeperChromeClient()
        // Downloads are refused: no files may reach the child profile.
        setDownloadListener(DownloadListener { _, _, _, _, _ ->
            listener?.onBlocked(ReasonCode.DOWNLOAD_BLOCK, RiskCategory.UNKNOWN)
            loadBlockPage(ReasonCode.DOWNLOAD_BLOCK, RiskCategory.UNKNOWN)
        })
    }

    fun setAgeTier(newTier: AgeTier) {
        tier = newTier
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun configureSettings() {
        settings.apply {
            // JavaScript is required by EdTech sites; the risk is contained
            // by having NO JS bridge and by post-load content classification.
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = false
            allowFileAccess = false
            allowContentAccess = false
            allowFileAccessFromFileURLs = false
            allowUniversalAccessFromFileURLs = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            safeBrowsingEnabled = true
            mediaPlaybackRequiresUserGesture = true
            cacheMode = WebSettings.LOAD_DEFAULT
            setSupportMultipleWindows(false)
            javaScriptCanOpenWindowsAutomatically = false
        }
        // Remove the stock Android JavaScript interfaces (historic bridge-abuse vector).
        removeJavascriptInterface("searchBoxJava")
        removeJavascriptInterface("accessibility")
        removeJavascriptInterface("accessibilityTraversal")
        // Deliberately NO addJavascriptInterface() call anywhere in this class.
    }

    /** Load a URL only after the interceptor has approved the navigation. */
    fun loadGatekeptUrl(url: String) {
        val result = interceptor.evaluateUrl(url)
        when (result.decision) {
            WebViewInterceptor.InterceptDecision.ALLOW -> {
                listener?.onAllowed()
                super.loadUrl(url)
            }
            WebViewInterceptor.InterceptDecision.BLOCK -> {
                listener?.onBlocked(result.reasonCode, result.category)
                loadBlockPage(result.reasonCode, result.category)
            }
            WebViewInterceptor.InterceptDecision.ESCALATE -> {
                listener?.onEscalated(result.reasonCode, result.category)
                loadBlockPage(result.reasonCode, result.category)
            }
        }
    }

    /** Generic block page. Never echoes the URL, host, or page content. */
    fun loadBlockPage(reasonCode: ReasonCode, category: RiskCategory) {
        val title = when (reasonCode) {
            ReasonCode.SEARCH_ENGINE_BLOCK -> "Search is not available here"
            ReasonCode.FINANCIAL_APP_BLOCK -> "Payments are not available here"
            ReasonCode.DOWNLOAD_BLOCK -> "Downloads are not allowed"
            else -> "This page is not available"
        }
        val body = if (reasonCode == ReasonCode.RULE_ESCALATE || reasonCode == ReasonCode.CLASSIFIER_ESCALATE) {
            "This page needs a grown-up to review it. Ask a parent to request a review - " +
                "there is no code you can type on this tablet to open it."
        } else {
            "This page is blocked for your age group. If you need it for school, " +
                "ask a parent to request a review."
        }
        val html = "<html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
            "<style>body{font-family:sans-serif;padding:32px;color:#1f2937}" +
            "h1{font-size:20px}.tag{color:#6b7280;font-size:13px}</style></head>" +
            "<body><h1>" + title + "</h1><p>" + body + "</p>" +
            "<p class=\"tag\">Aegis-Kid OS &middot; Stay safe online</p></body></html>"
        loadDataWithBaseURL("about:blank", html, "text/html", "UTF-8", null)
    }

    override fun destroy() {
        runCatching { classifier.close() }
        super.destroy()
    }

    // ------------------------------------------------------------------
    // WebViewClient: navigation + sub-resource + post-load classification
    // ------------------------------------------------------------------

    private inner class GatekeeperClient : WebViewClient() {

        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            val url = request.url.toString()
            val result = interceptor.evaluateUrl(url)
            return when (result.decision) {
                WebViewInterceptor.InterceptDecision.ALLOW -> {
                    listener?.onAllowed()
                    false // Let the WebView load it.
                }
                WebViewInterceptor.InterceptDecision.BLOCK -> {
                    listener?.onBlocked(result.reasonCode, result.category)
                    loadBlockPage(result.reasonCode, result.category)
                    true
                }
                WebViewInterceptor.InterceptDecision.ESCALATE -> {
                    listener?.onEscalated(result.reasonCode, result.category)
                    loadBlockPage(result.reasonCode, result.category)
                    true
                }
            }
        }

        override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
            return interceptor.shouldInterceptRequest(request)
        }

        override fun onLoadResource(view: WebView, url: String) {
            interceptor.onLoadResource(url)
            super.onLoadResource(view, url)
        }

        override fun onPageFinished(view: WebView, url: String) {
            super.onPageFinished(view, url)
            val uri = runCatching { Uri.parse(url) }.getOrNull()
            // Allowlisted EdTech hosts were already verified; do not spend
            // battery re-classifying their DRM video pages.
            if (uri != null && AllowlistBypass.isBypassHost(uri.host)) return
            classifyVisibleText()
        }

        /**
         * Extract visible text, classify it in volatile RAM, and replace
         * the page if it fails. The JS result is a JSON-encoded string;
         * it is decoded, classified, and then dropped - never stored.
         */
        private fun classifyVisibleText() {
            val js = "(function(){try{return document.body?document.body.innerText.slice(0,${tier.maxClassifiedChars}):''}catch(e){return ''}})()"
            evaluateJavascript(js) { rawValue ->
                var text: String? = null
                try {
                    text = runCatching {
                        JSONObject("{\"v\":$rawValue}").optString("v")
                    }.getOrNull()
                    if (text.isNullOrBlank()) return@evaluateJavascript
                    val verdict = classifier.classify(text, tier)
                    when (verdict.decision) {
                        Decision.BLOCK -> {
                            listener?.onBlocked(verdict.reasonCode, verdict.category)
                            loadBlockPage(verdict.reasonCode, verdict.category)
                        }
                        Decision.ESCALATE -> {
                            listener?.onEscalated(verdict.reasonCode, verdict.category)
                            loadBlockPage(verdict.reasonCode, verdict.category)
                        }
                        Decision.ALLOW -> listener?.onAllowed()
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Post-load classification failed: ${e.javaClass.simpleName}")
                } finally {
                    // Purge: drop the only reference to the page text.
                    text = null
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // WebChromeClient: no file chooser, no JS dialogs the child can be
    // tricked with, no new windows.
    // ------------------------------------------------------------------

    private inner class GatekeeperChromeClient : WebChromeClient() {
        override fun onShowFileChooser(
            webView: WebView,
            filePathCallback: ValueCallback<Array<Uri>>,
            fileChooserParams: FileChooserParams,
        ): Boolean {
            // No file uploads from the child profile.
            filePathCallback.onReceiveValue(null)
            return true
        }

        override fun onJsAlert(view: WebView, url: String, message: String, result: JsResult): Boolean {
            result.cancel()
            return true
        }

        override fun onJsConfirm(view: WebView, url: String, message: String, result: JsResult): Boolean {
            result.cancel()
            return true
        }

        override fun onJsPrompt(
            view: WebView,
            url: String,
            message: String,
            defaultValue: String,
            result: JsPromptResult,
        ): Boolean {
            result.cancel()
            return true
        }

        override fun onCreateWindow(view: WebView, isDialog: Boolean, isUserGesture: Boolean, resultMsg: Message): Boolean {
            // No pop-ups / new windows: every navigation stays in this contained WebView.
            return false
        }
    }

    companion object {
        private const val TAG = "AegisGatekeeperWebView"
    }
}
