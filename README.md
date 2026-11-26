# Aegis-Kid OS (India Edition) — MVP

An un-bypassable, zero-override, AI-gated operating environment for kids' tablets in India, built on Android Enterprise Device Owner mode, with an offline-first on-device safety gatekeeper and a FastAPI backend for DigiLocker verification, heartbeat / tamper alerts, and AI adjudication.

Target hardware: Android Enterprise Recommended (AER) budget-to-midrange tablets (e.g. Lenovo Tab M-series, Samsung Galaxy Tab A-series, 3–4 GB RAM, Android 12–16+). Age tiers: 5–8, 9–12, 13–15, 16–17.

> **Status: partial MVP — read this before building.**
>
> Deliverables 1, 3, 4 and 5 below are in this repo. **Deliverable 2 — the Android Device Owner DPC & Kiosk Launcher (DeviceAdminReceiver, DevicePolicyManager restrictions, LockTask launcher, VpnService DNS/SNI firewall) — is NOT in this repo.** That work was flagged and removed during generation and was not rebuilt. That is a blocker for the full MVP as specified: without it there is no Device Owner lockdown, no kiosk, and no VPN firewall, and the Android app in this repo is **not buildable as a standalone app** (no `AndroidManifest.xml`, no Gradle files — see `android/` notes below).
>
> What *is* here can still be reviewed, tested (backend: 22/22 tests pass), and used as the design + backend + gatekeeper/security-module foundation.

## What is in this repo

| # | Deliverable | Location | Status |
|---|-------------|----------|--------|
| 1 | DPDP-compliant system architecture & threat model | `docs/` | Done |
| 2 | Android Device Owner DPC & Kiosk Launcher (Kotlin) | — | **Missing — not built** |
| 3 | Offline-first LiteRT multilingual AI gatekeeper (Kotlin) | `android/app/src/main/java/com/aegis/kid/gatekeeper/` | Done, modules only |
| 4 | Hardware Keystore & Ed25519 policy verifier (Kotlin) | `android/app/src/main/java/com/aegis/kid/security/` | Done, modules only |
| 5 | Central watchdog, AI adjudicator & parent alert backend (Python FastAPI) | `backend/` | Done, tested |

## Privacy — DPDP Act, zero cloud logging

India's Digital Personal Data Protection (DPDP) Act (full enforcement from 13 May 2027) covers all minors under 18 and bans behavioural tracking of children. This design enforces that:

- **Never leaves the device:** browsing history, app usage logs, screenshots, search queries, voice/text inputs.
- All AI inspection, OCR and content classification runs 100% locally in volatile RAM and is purged immediately after the allow/block verdict.
- **Only these leave the device:** the 6-field heartbeat (`device_id`, `keystore_signature`, `battery_pct`, `network_state`, `boot_count`, `timestamp`); an unblock challenge containing only the target URL/package ID + `age_tier` + nonce (no PII, no free text — prompt-injection defence); and parent DigiLocker verification (parent only, never child data).
- See `docs/dpdp-compliance-checklist.md` and `docs/data-flow-diagram.md` for the full MAY-leave / NEVER-leave tables. Pre-release sign-off requires a qualified Indian data-privacy lawyer's review.

## Repo layout

```
aegis-kid-os/
├── README.md
├── docs/
│   ├── 01-architecture-threat-model.md   # architecture, components C1-C13, STRIDE T-01..T-17
│   ├── data-flow-diagram.md             # Mermaid diagrams, 5 sequence diagrams
│   ├── age-tier-policies.md             # policy matrix for 5-8 / 9-12 / 13-15 / 16-17
│   └── dpdp-compliance-checklist.md     # DPDP mapping + pre-release sign-off gate
├── android/
│   ├── GATEKEEPER.md                     # gatekeeper architecture, RAM budget, test plan
│   ├── SECURITY.md                       # key lifecycle, token verification, wire contract
│   └── app/src/main/java/com/aegis/kid/
│       ├── gatekeeper/                   # LiteRT classifier, WebView containment, OCR, Hinglish
│       └── security/                     # Keystore, Ed25519 sign/verify, heartbeat, watchdog
│       # NOTE: no AndroidManifest.xml, no build.gradle.kts, no DPC/launcher/VPN yet
└── backend/                              # FastAPI — see backend/README.md
    ├── app/                              # main, config, models, crypto, heartbeat, adjudicator,
    │                                     # digilocker, alerts, human_queue, db, routers
    ├── tests/                            # pytest — 22 tests
    ├── requirements.txt, pyproject.toml, Dockerfile, docker-compose.yml
    └── .env.example                      # placeholders only, no real credentials
```

## Backend — run it

```bash
cd backend
cp .env.example .env   # fill in real values; DigiLocker mock mode is on by default
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                # 22 passed
uvicorn app.main:app --reload
```

Endpoints (see `backend/README.md` for the full table): `POST /api/v1/heartbeat`, `GET /api/v1/devices/{id}/status`, `POST /api/v1/unblock/request`, `POST /api/v1/digilocker/verify`, `POST /api/v1/support/escalate`.

Key rules implemented: unblock auto-approve only at confidence ≥ 0.98 for age-appropriate resources, 24-hour single-resource Ed25519 tokens; social/messaging, permanent unlocks, tier upgrades and un-enrollment escalate to a human queue after DigiLocker parent re-verification; `CRITICAL_TAMPER_BREACH` via WhatsApp Business + SMS, suppressed for battery ≤ 5% graceful shutdowns and brief (< 30 min) offline gaps.

Without `ED25519_PRIVATE_KEY_B64` the server generates an ephemeral signing key and logs a warning — tokens will not verify after a restart. Generate a persistent key before any real deployment. `POST /api/v1/devices/register` is provisioning-only and has no auth in this MVP — add provisioning auth before production use.

## Android modules — what they are / are not

- **Gatekeeper** (`gatekeeper/`): LiteRT/MediaPipe quantized classifier (< 300 MB RAM budget), contained `WebView`, low-power on-device OCR screen-guard, Hinglish / Hindi / Telugu / Tamil detection, signature-verified EdTech allowlist bypass (PW, NCERT/DIKSHA, Khan Academy, Unacademy, BYJU'S/Aakash, YouTube Kids). **No trained `.tflite` model is included** — protection today is the rule-based fallback + allowlist. Certificate hashes are placeholders and must be pinned from real Play Store signing fingerprints. See `android/GATEKEEPER.md`.
- **Security** (`security/`): non-exportable Ed25519/EC key in Android Keystore (StrongBox preferred, TEE fallback), heartbeat signing (exactly the 6 fields), offline Ed25519 token verification, offline heartbeat cache in EncryptedSharedPreferences, foreground watchdog (10-min loop; WorkManager minimum is 15 min, so it is only a restart guard). Backend public key is a placeholder and must be replaced at provisioning. See `android/SECURITY.md` §6 for the canonical-JSON wire contract — this is the contract the backend verifies against.
- **Two `AgeTier` enums exist** (`gatekeeper` and `security`, same member names, different packages). Converge on one shared enum before wiring the gatekeeper to verified tokens.
- No Android SDK was present in the build environment, so the Kotlin was not Gradle-compiled — a Gradle build in Android Studio is still needed.

## Known limitations (from the docs)

- WorkManager cannot do a 10-minute interval (15-min minimum) — the 10-min heartbeat is a foreground-service loop.
- A recovery wipe cannot be prevented, only detected (EFRP + attestation / `boot_count`) and alerted on.
- LiteRT classification is probabilistic, not 100%; keyword lists need native-speaker review per language.
- OCR needs a frame source (MediaProjection / AccessibilityService) — that capture was to come from the missing DPC module.
- No location tracking, no screen recording, no offline unblock, no local parent PIN/bypass by design.

## Secrets

None in this repo. All credentials are via environment variables / placeholders (`${DIGILOCKER_CLIENT_ID}`, `${BACKEND_ED25519_PRIVATE_KEY}`, `${WHATSAPP_BUSINESS_API_TOKEN}`, etc.). Never commit a real `.env`, keystore, or API token.
