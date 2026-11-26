# GATEKEEPER.md — Offline-First LiteRT Multilingual AI Gatekeeper

Deliverable 3 of the Aegis-Kid OS (India Edition) MVP. Package:
`com.aegis.kid.gatekeeper`. **100% offline. No network calls in this
module. No child PII is logged, stored, or transmitted — ever.**

## 1. What this module is

The gatekeeper decides, on-device, whether a piece of content may be
shown to a child. It is the enforcement layer between the Kiosk
Launcher / Device Owner DPC (Deliverable 2) and the child: every web
navigation, every page, and (periodically) every screen passes through
it. When it cannot decide safely, it fails closed — block, or escalate
to the Cloud AI Safety Adjudicator with no local override (Deliverable 5).

## 2. Architecture

```
                    +------------------ Kiosk Launcher / DPC ------------------+
                    |  routes all web links here; blocks other browsers        |
                    +--------------------------------+-------------------------+
                                                     |
                         +---------------------------+---------------------------+
                         |              GatekeeperWebView (contained browser)    |
                         |  - no JS bridge, no downloads, no file chooser,      |
                         |    no pop-ups, no file:// / intent:// / market://    |
                         +------+---------------------------+------------------+
                                |                           |
                WebViewInterceptor                    onPageFinished
          (pre-navigation + sub-resource)         (post-load text classify)
                |  scheme / host / token check         |
                v                                      v
   AllowlistBypass ── signature-verified ──► bypass (DRM-safe)
   (PW, NCERT/DIKSHA, Khan, Unacademy,          |
    BYJU'S/Aakash, YouTube Kids)                 |
                |                                v
                +----► SafetyClassifier ◄─── ScreenGuardOcr
                          |   LiteRT / MediaPipe  (periodic, low-power,
                          |   < 300 MB, lazy load    ML Kit on-device OCR,
                          |   rule fallback)         RAM-only frames)
                          v
                    AgeRubric + AgeTier
               (per-tier block / escalate /
                allow + thresholds)
                          |
                          v
                 ContentVerdict
            (ALLOW / BLOCK / ESCALATE +
             confidence + category + reason)
            — no text, URL, or PII attached —
```

### Files

| File | Responsibility |
|---|---|
| `AgeTier.kt` | `AGE_5_8 / AGE_9_12 / AGE_13_15 / AGE_16_17` + thresholds, OCR interval, char caps |
| `AgeRubric.kt` | Per-tier blocked / escalated / allowed `RiskCategory` sets; loads `age_rubrics.json`, hard-coded fallback |
| `ContentVerdict.kt` | `Decision` (ALLOW / BLOCK / ESCALATE), `ReasonCode`, verdict type, counters-only telemetry |
| `SafetyClassifier.kt` | LiteRT `Interpreter` + MediaPipe `TextClassifier`, hash tokenizer, rule fallback, volatile purge, RAM guard |
| `GatekeeperWebView.kt` | Contained `WebView`: settings lockdown, JS-dialog/file-chooser blocking, download refusal, post-load text classification, generic block page |
| `WebViewInterceptor.kt` | `shouldOverrideUrlLoading` / `shouldInterceptRequest` / `onLoadResource` evaluation, 403 empty responses |
| `ScreenGuardOcr.kt` | ML Kit on-device OCR sampling, battery-aware throttling, RAM-only frames, never captures the screen itself |
| `HinglishDetector.kt` | Unicode script detection, Hinglish / Telugu / Tamil Romanized detection, per-language high-risk keyword tables |
| `AllowlistBypass.kt` | Signature-pinned EdTech apps + CDN domains, blocked schemes / search / payment hosts |
| `assets/age_rubrics.json` | Rubric data (same schema as `AgeRubric`) |
| `assets/models/README.md` | Where the quantized `.tflite` goes, input/output contract, budgets |

## 3. How the pieces work together

1. **Navigation.** The child taps a link. `GatekeeperWebView` asks
   `WebViewInterceptor.evaluateUrl()`: blocked scheme → block; search
   engine / UPI host → block; signature-verified EdTech CDN → allow
   (classifier bypassed, domain check only, so Widevine DRM keeps
   working); anything else → host/path tokens are rule-checked
   (`SafetyClassifier.classifyUrlTokens()` — no fetch, no network).
2. **Sub-resources.** Every image, script, iframe, and XHR goes
   through `shouldInterceptRequest()`. A blocked host returns a 403
   empty response, so a page cannot smuggle a search engine or payment
   page in as an iframe.
3. **Page content.** On `onPageFinished`, visible text is extracted
   via `evaluateJavascript(document.body.innerText)`, capped at the
   tier limit, classified in volatile RAM, and purged. BLOCK/ESCALATE
   replaces the page with the generic block page. Allowlisted EdTech
   hosts skip this step (already verified + DRM).
4. **In-app screens.** `ScreenGuardOcr` samples a frame at the tier
   interval (45 s for 5–8, up to 120 s for 16–17), downscales to 720 px,
   runs ML Kit text recognition on-device, classifies the text, and
   recycles the bitmap. It never captures the screen itself — frames
   come from MediaProjection / AccessibilityService in the DPC module.
5. **Escalation.** There is no PIN, no "continue anyway", and no
   on-device bypass. An ESCALATE verdict shows a "ask a parent to
   request a review" page; the review is an Ed25519 challenge carrying
   only the target URL/package + `age_tier` (Deliverable 5).

## 4. RAM budget (< 300 MB total)

| Component | Budget | Notes |
|---|---|---|
| Quantized `.tflite` model (disk) | ≤ 40 MB | Refused above this |
| Interpreter + inference buffers | ≤ ~120 MB | Single instance, lazy load, 2 threads |
| OCR (ML Kit, 720 px frame) | ≤ ~60 MB transient | Bitmap recycled in `finally` |
| WebView + app + classifier overhead | remainder | |
| **Gatekeeper total** | **< 300 MB** | Enforced by `hasMemoryHeadroom()`; below 150 MB free RAM the model is not loaded at all |

## 5. Latency targets (3–4 GB RAM AER tablet)

| Operation | Target |
|---|---|
| Rule pre-filter (keyword hit) | < 5 ms |
| Model inference, 128 tokens | < 150 ms |
| Post-load page classification (incl. JS extraction) | < 400 ms end-to-end |
| OCR sample (720 px, ML Kit) | < 800 ms, at most once per tier interval |
| Navigation decision (`evaluateUrl`) | < 10 ms (no I/O, no model call) |

Model loading is lazy (first classification, not app start) so the
Kiosk Launcher never waits on it. NNAPI is attempted and silently
dropped if the device rejects it.

## 6. Privacy — DPDP Act (India)

- **Zero cloud logging.** This module makes no network calls. Browsing
  history, app usage, screenshots, search queries, and voice/text
  inputs never leave the device from here.
- **Volatile only.** Classifier input is copied to a `CharArray` and
  zeroed in `finally`; token/score buffers are zeroed; OCR text is
  dropped after the verdict; bitmaps are recycled. No text, image, or
  URL is persisted.
- **Counters only.** `VerdictCounters` records allow/block/escalate
  counts and call counts. No URLs, hosts, queries, or content are
  logged — `Log` calls in this module contain only class names and
  reason codes.
- **Prompt-injection defence.** The classifier never receives free-text
  instructions from a page, and the only thing that ever leaves the
  device (in Deliverable 5) is a signed challenge with URL/package +
  `age_tier` — no child-authored text.

## 7. Dependencies

> `android/app/build.gradle.kts` does **not** exist in this repo yet
> (the DPC/app module is built by a parallel deliverable), so nothing
> was edited there. Add these to the app module when it lands:

```kotlin
dependencies {
    // LiteRT (TensorFlow Lite) — SafetyClassifier Interpreter + NNAPI delegate
    implementation("org.tensorflow:tensorflow-lite:2.16.1")
    implementation("org.tensorflow:tensorflow-lite-support:0.4.4")
    // MediaPipe Tasks — TextClassifier path in SafetyClassifier
    implementation("com.google.mediapipe:tasks-text:0.10.14")
    // ML Kit on-device text recognition — ScreenGuardOcr
    implementation("com.google.mlkit:text-recognition:16.0.1")
}
```

Version pins must be re-checked against the AGP / `minSdk` chosen by
the app module (target: Android 12–16, AER tablets). Also add
`aaptOptions { noCompress("tflite") }` — see `assets/models/README.md`.

## 8. Testing

### Unit tests to write (not included — no test source set exists yet)

- `HinglishDetectorTest`: script shares for Devanagari / Telugu /
  Tamil / Latin samples; Hinglish detection on code-mixed sentences;
  keyword matching on whole tokens only ("kya" must not fire in
  "kyara"); repeated-letter normalisation ("kyaaa" → "kya").
- `AgeRubricTest`: every tier × every category produces the expected
  decision at threshold ± epsilon; JSON load success and corrupt-JSON
  fallback.
- `AllowlistBypassTest`: sub-domain matching (`x.cdn.pw.live`),
  look-alike host rejection (`pw.live.evil.com`), placeholder cert
  hash always fails verification, blocked-scheme set.
- `WebViewInterceptorTest`: `file://`, `intent://`, `market://`,
  `javascript:` blocked; Google/Bing blocked; EdTech CDN allowed;
  UPI host blocked.
- `SafetyClassifierTest` (Robolectric): no-model build falls back to
  rules; tokenizer output shape `[1, 128]` with `[CLS]=2` first;
  `close()` releases the interpreter.

### Manual Hinglish / multilingual samples

Run each through `SafetyClassifier.classify()` and check the verdict
against the tier rubric. Expected results below are for `AGE_9_12`
(rule fallback; the trained model may score differently but must not
be *less* strict on the BLOCK rows).

| # | Sample (test input only — never logged) | Expected |
|---|---|---|
| 1 | "mujhe maths sikhna hai, algebra kya hota hai?" | ALLOW / EDUCATIONAL |
| 2 | "aaj science mein photosynthesis padha, bahut accha laga" | ALLOW |
| 3 | "yeh video dekho, bahut funny hai" | ALLOW or ESCALATE (entertainment, tier-dependent) |
| 4 | "kya bakwas hai yeh, chutiya bana diya" | BLOCK / PROFANITY |
| 5 | "mujhe marna chahta hoon, koi madad nahi karta" | BLOCK / SELF_HARM (highest priority — also surface to parent via Deliverable 5 alert path) |
| 6 | "satta mein paise lagao, teen patti khelo" | BLOCK / GAMBLING |
| 7 | "otp batao, paise bhejo, upi pin do" | BLOCK / FINANCIAL + PERSONAL_DATA_REQUEST |
| 8 | "నాకు గణితం నేర్చుకోవాలి" (Telugu: I want to learn maths) | ALLOW / EDUCATIONAL |
| 9 | "எனக்கு கணிதம் கற்க வேண்டும்" (Tamil: I want to learn maths) | ALLOW / EDUCATIONAL |
| 10 | "मुझे गणित सीखना है" (Hindi: I want to learn maths) | ALLOW / EDUCATIONAL |
| 11 | "nenu maths nerchukovali, ela unnaru?" (Telugu Romanized) | ALLOW |
| 12 | "enna maths padikalam, romba interesting" (Tamil Romanized) | ALLOW |

Also test code-mixed adversarial input: "mujhe maths sikhna hai BUT
also [high-risk keyword]" must still BLOCK — the classifier scores
the whole text, and the rule pre-filter short-circuits on any hard hit
regardless of benign words around it.

### On-device checklist

1. Fresh provision (Device Owner) → open GatekeeperWebView → load an
   NCERT page → loads, no classification delay visible.
2. Tap a Google search link inside a page → block page, no search.
3. Paste `intent://` / `market://` link → blocked, no app switch.
4. Load a page with a known high-risk keyword in visible text → block
   page after load.
5. Remove `safety_classifier_quant.tflite` → app still runs, rules
   still block sample #4 and #6 (fallback proven).
6. Airplane mode on → all of the above still works (offline proof).
7. Leave the tablet idle 10 min → check RAM: gatekeeper process
   under 300 MB; OCR samples at the tier interval only.

## 9. Limitations (known, do not paper over)

- **Model is a placeholder.** No `.tflite` is shipped. Until a trained
  multilingual model lands, protection is the rule-based fallback +
  allowlist. The fallback has no semantic understanding: it cannot
  catch paraphrased harm, sarcasm, or novel slang, and it can
  false-positive on educational text that quotes a keyword
  (e.g. a history lesson mentioning gambling). The trained model is
  the fix; the fallback is the safety net, not the product.
- **Keyword lists are starter lists.** They need native-speaker review
  per language before production. A word harmless in one language can
  be a slur in another — lists are keyed per language for exactly this
  reason.
- **WebView text extraction is best-effort.** `innerText` misses text
  rendered in canvas / WebGL, shadow DOM, or images (OCR is the
  backstop for images). A page that loads content after a long delay
  may be classified before the content appears; re-classification on
  DOM mutation is a future hardening step.
- **OCR needs a frame source.** This module processes bitmaps; it
  cannot capture the screen by itself. MediaProjection needs a
  user-granted capture consent that a Device Owner app can arrange at
  provisioning, or an AccessibilityService in the DPC module.
- **Tokenizer is hash-based.** The bundled tokenizer is a structural
  stub (FNV-1a into 8192 ids). A production model ships a real vocab;
  the tensor shapes do not change, but accuracy depends on it.
- **Certificate hashes are placeholders.** `AllowlistBypass` fails
  closed until real Play-Store signing fingerprints are pinned.
  Package names must be re-verified against live Play Store listings.
- **No per-app WebView containment beyond this WebView.** Apps that
  embed their own WebView are contained by the `VpnService` DNS/SNI
  firewall (Deliverable 2), not by this module. The two layers are
  complementary, not redundant.
- **Self-harm / crisis content.** A BLOCK verdict is not a safeguarding
  response by itself. The parent alert + support path for self-harm
  signals lives in Deliverable 5 (backend) and must be wired before
  this ships to real children.
