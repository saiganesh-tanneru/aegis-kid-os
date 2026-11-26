# Quantized Safety Classifier Model — Placement Guide

> **The model file is NOT included in this repo.** This directory ships
> empty on purpose: the model is a trained artefact with its own licence,
> training data, and evaluation report. Place the built file here during
> the release build; the classifier falls back to the rule-based engine
> (`HinglishDetector` keyword tables) when it is absent, so a build
> without the model still runs, strictly.

## File to place here

| Item | Value |
|---|---|
| File name | `safety_classifier_quant.tflite` |
| Expected path | `android/app/src/main/assets/models/safety_classifier_quant.tflite` |
| Size budget | **<= 40 MB** (quantized int8; refused above this, see `SafetyClassifier.MODEL_SIZE_BUDGET_BYTES`) |
| SHA-256 | `TODO: <fill in after the release model is built — do not ship with a placeholder hash>` |
| Format | LiteRT / TensorFlow Lite, int8-quantized weights |

## Model contract (must match `SafetyClassifier.kt` exactly)

- **Input tensor 0:** `int32[1, 128]` — token ids.
  - Tokenizer: NFKC + lower-case, `[CLS]=2` first, `[SEP]=3` after the
    last word, `[PAD]=0` fill, `[UNK]=1` for out-of-vocab words.
    The bundled `SafetyClassifier.tokenize()` is a **hash-based stub**
    (FNV-1a into an 8192-word vocab). A production model ships a real
    vocab file and this function is replaced by a lookup into it — the
    tensor shapes do **not** change.
  - Max sequence length: 128 tokens. Longer text is truncated to the
    age-tier character cap first (`AgeTier.maxClassifiedChars`), then
    tokenized.
- **Output tensor 0:** `float32[1, 23]` — one score in `[0, 1]` per
  `RiskCategory` enum entry, **in enum declaration order**:
  `EDUCATIONAL, KIDS_ENTERTAINMENT, GENERAL_ENTERTAINMENT, SOCIAL_MEDIA,
  MESSAGING, VIDEO_STREAMING, GAMING, NEWS, SEARCH_ENGINE, SHOPPING,
  FINANCIAL, ADULT_SEXUAL, VIOLENCE, SELF_HARM, SUBSTANCE_USE, GAMBLING,
  HATE_EXTREMISM, WEAPONS, PROFANITY, DATING, ANONYMOUS_CHAT,
  PERSONAL_DATA_REQUEST, UNKNOWN`.
  - If the model exports int8 outputs instead, add dequantization
    (`(value - zero_point) * scale`) in `SafetyClassifier.runInterpreter()`
    and keep the float contract above at the call site.
  - Adding, removing, or reordering a category is a **breaking change**:
    bump `AgeTier.POLICY_VERSION`, update `age_rubrics.json`, and retrain.
- **Alternative path:** if the model is a MediaPipe text-classifier
  bundle, `SafetyClassifier` tries `TextClassifier.createFromFileAndOptions`
  first and uses the top category name (which must equal a `RiskCategory`
  name). The raw-LiteRT path above is the default.

## Training requirements (for the model owner, not this repo)

- Multilingual training data: English, Hindi (Devanagari), Hinglish
  (Romanized Hindi), Telugu, Tamil, plus Bengali / Kannada / Malayalam
  where data exists. Code-mixed samples (Hinglish + English in one
  sentence) must be a first-class slice, not an afterthought.
- Labels: the 23 `RiskCategory` values above, with per-age-tier
  evaluation (a page that is fine for 16-17 may be a block for 5-8).
- Evaluation gates before a model ships: false-negative rate on the
  `ADULT_SEXUAL`, `SELF_HARM`, and `VIOLENCE` slices must be measured
  per language, and the model must not be worse than the rule-based
  fallback on any slice. The fallback stays in the build as a safety net.
- No child PII in training data. Ever.

## Build note

`.tflite` files must not be compressed by AAPT, or `openFd()` fails at
runtime. Add this to the `android {}` block in `app/build.gradle.kts`:

```kotlin
aaptOptions {
    noCompress("tflite")
}
```

## RAM budget

| Component | Budget |
|---|---|
| Quantized model file | <= 40 MB on disk |
| Interpreter + working buffers | <= ~120 MB at inference |
| OCR (ML Kit, downscaled 720px) | <= ~60 MB transient |
| WebView + app | remainder |
| **Gatekeeper total** | **< 300 MB** (`SafetyClassifier.TOTAL_RAM_BUDGET_BYTES`) |

If free RAM falls below 150 MB at load time, the classifier refuses to
load the model and serves the rule-based fallback instead of risking an
OOM kill of the Kiosk Launcher.
