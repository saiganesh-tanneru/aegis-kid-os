# Aegis-Kid OS (India Edition) — Deliverable 1
## DPDP-Compliant System Architecture & Threat Model

| Field | Value |
|---|---|
| Document | `docs/01-architecture-threat-model.md` |
| Version | 1.0.0 — MVP |
| Date | 2026-11-25 |
| Status | **Authoritative for MVP build** — Deliverables 2–5 must implement this document; any deviation requires an architecture change record |
| Scope | Android Enterprise Device Owner (QR provisioning), Zero-Touch-ready; AER tablets, Android 12–16+, 3–4 GB RAM |
| Companion docs | `docs/data-flow-diagram.md` (Mermaid data-flow + sequence diagrams), `docs/age-tier-policies.md` (policy matrix), `docs/dpdp-compliance-checklist.md` (DPDP mapping) |
| Audience | Android / DPC engineers, backend engineers, security reviewer, DPDP compliance reviewer, Human Support Team |
| Classification | Internal — contains no secrets, no real credentials. All credentials are placeholders, e.g. `${DIGILOCKER_CLIENT_ID}` |

> **One-line design rule:** *Nothing about what a child does, reads, types, watches, or says ever leaves the device. Only three things may leave, and only in the exact shapes defined in §6: (1) a signed, zero-PII heartbeat, (2) a signed unblock challenge containing only a URL/package ID + age tier, and (3) a parent's own DigiLocker verification (parent data, never child data).*

---

## 1. Executive Summary

Aegis-Kid OS is not a parental-control app. It is a **Device Owner (DO) operating environment** that replaces the normal Android experience on a child's tablet with a locked-down kiosk, a local AI gatekeeper, and a hardware-bound watchdog. A normal app can be uninstalled, force-stopped, or bypassed in Safe Mode. A Device Owner cannot — short of a hardware-level exploit or a factory reset via recovery, both of which are detected and alarmed on (see §8, T-04, T-15).

The MVP is deliberately narrow:

- **One device class:** Android Enterprise Recommended (AER) budget-to-midrange tablets (Lenovo Tab M-series, Samsung Galaxy Tab A-series, 3–4 GB RAM, Android 12–16+). AER devices are chosen specifically to avoid aggressive OEM background-service killing (MIUI / ColorOS / similar) that would silently kill the watchdog and firewall during MVP validation. Non-AER devices are out of scope for MVP.
- **One enrolment path for MVP:** QR-code Device Owner provisioning (`DevicePolicyManager`, `ACTION_PROVISION_MANAGED_DEVICE`). Zero-Touch Enrollment is architecturally supported (same DPC, same policies, enrolment via ZTE config) but is **not** the MVP validation path.
- **One trust model:** The child is the *adversary* for bypass resistance; the parent is the *account holder* for consent and escalation; the backend is *untrusted for child data* — it never receives child data, so it cannot leak it.
- **One AI model:** A fully offline, quantized Google LiteRT / MediaPipe classifier (< 300 MB RAM total, including OCR screen-guard) that runs in volatile RAM only. There is no cloud content inspection for children in the MVP. The Cloud AI Safety Adjudicator (§4.9) adjudicates only *unblock requests* — a URL/package ID and an age tier — never content, history, or free text.

### 1.1 Design principles

| # | Principle | What it forces |
|---|---|---|
| P1 | **Privacy by design, not by policy** | Child data cannot leave because no code path exists to send it. See §6. |
| P2 | **Zero local override** | No parent PIN, no device-side bypass, no "emergency unlock" on the device. Every exception is a signed, time-bound, single-resource token issued off-device or by a human after re-verification. |
| P3 | **Fail closed** | If the firewall, classifier, Keystore, or watchdog is unavailable, traffic is blocked and the kiosk stays locked. The device never degrades to an open tablet. |
| P4 | **Offline-first** | All enforcement works with no network. The cloud is only for (a) heartbeat intake, (b) unblock adjudication, and (c) breach alerts. A child on a train with Wi-Fi off is still protected. |
| P5 | **Hardware-bound identity** | The device identity is a non-exportable Keystore key in TEE / StrongBox, not a stored token or a device ID that can be copied to another tablet. |
| P6 | **Least privilege, per age tier** | Four cryptographically bound policy profiles (5–8, 9–12, 13–15, 16–17). A 6-year-old and a 16-year-old do not get the same internet. See `docs/age-tier-policies.md`. |
| P7 | **Probabilistic AI, deterministic enforcement** | LiteRT is a classifier with a confidence score, not a guarantee. The allowlist, the DNS/SNI firewall, and the token verifier are deterministic and are the ultimate gate. |

### 1.2 What the MVP is and is not

| MVP does | MVP does NOT do (see §10 Non-Goals) |
|---|---|
| Lock a tablet into a kiosk launcher at boot | Replace Android or ship a custom ROM / AOSP fork |
| Filter all web traffic through a local AI gatekeeper + DNS/SNI firewall | Deep-packet-inspect (DPI) DRM video streams inside allowlisted EdTech apps |
| Allow signature-verified EdTech apps + their CDNs to bypass DPI (not the firewall) | Guarantee protection against hardware-level / bootloader exploits |
| Sign heartbeats in hardware and alert on tamper | Track location, read messages, or record a child's screen |
| Issue 24-hour, single-resource unblock tokens via Ed25519 | Let a parent unlock anything locally with a PIN |
| Verify a parent via DigiLocker before binding | Store or transmit any child's browsing history, app usage, screenshots, search queries, or voice/text input |

---

## 2. Target Platform & Constraints

### 2.1 Hardware / OS baseline

| Item | MVP requirement | Rationale |
|---|---|---|
| Device class | Android Enterprise Recommended (AER) tablets | Guaranteed DO support, timely patches, predictable background-service behaviour |
| Examples | Lenovo Tab M-series, Samsung Galaxy Tab A-series | Budget–midrange; representative of the India MVP market |
| RAM | 3–4 GB | Gatekeeper budget is < 300 MB total; the rest is for the OS, launcher, and one foreground EdTech app |
| Android | 12–16+ (API 31–36) | `DISALLOW_SAFE_BOOT`, per-app streaming controls, and modern `DevicePolicyManager` APIs require API 31+; see §3.3 for API notes |
| Storage | ≥ 32 GB, encrypted (file-based encryption on by default) | Heartbeat cache + LiteRT models + allowlist must fit without user data |
| Security hardware | TEE required; StrongBox preferred, fall back to TEE if absent | Keystore attestation and non-exportable signing key (§4.7) |
| Connectivity | Wi-Fi; optional LTE (SIM present but SIM/APN settings locked) | Heartbeat and unblock requests need intermittent connectivity only |
| Out of scope | MIUI / ColorOS / other aggressive OEM skins, phones, Chromebooks, rooted devices, devices without a lockable bootloader | OEM background killing and non-standard DO behaviour break the watchdog/firewall guarantees |

### 2.2 Performance / resource budgets (hard limits)

| Budget | Limit | Enforcement |
|---|---|---|
| Gatekeeper total RAM | < 300 MB (LiteRT classifier + OCR screen-guard + WebView interceptor, combined, steady state) | Quantized int8 models only; single model instance; OCR runs at low frequency, not per frame; see Deliverable 3 spec |
| Heartbeat | Every 10 min, ≤ 1 KB per packet, WorkManager + ForegroundService | Batch-sync only on reconnect; no wake-up more often than 10 min |
| Battery | Watchdog + firewall must not exceed ~2% battery per 24 h idle (target; measure in MVP validation) | Foreground service with low-priority notification; no polling loops; WorkManager constraints |
| Boot to kiosk | ≤ 30 s from power-on to locked launcher on reference hardware | No heavy init before `LockTask` starts |
| Unblock verdict (local) | ≤ 500 ms for allowlist hit; ≤ 2 s for LiteRT classification of a page | If classification exceeds the timeout, fail closed (block) and log a local, child-anonymous counter only |
| Token verification (offline) | ≤ 50 ms, Ed25519 verify with cached backend public key | No network call on the enforcement path |

### 2.3 Assumptions

1. The tablet is **factory-reset and unprovisioned** at enrolment. QR provisioning cannot convert an already-personal device without a reset.
2. The parent has a DigiLocker account and a phone number capable of receiving WhatsApp / SMS for breach alerts. The child has no phone number on file.
3. The parent performs enrolment in person, with the tablet in hand, on a trusted network for the first sync.
4. Google Play Services are present (AER requirement) for Zero-Touch readiness, but **no Aegis function depends on Play Services at runtime** for enforcement — enforcement is local.
5. The backend public Ed25519 key is pinned in the DPC at provisioning time and rotated only via a signed policy update (see §4.8).

---

## 3. System Architecture

### 3.1 Architecture at a glance

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CHILD'S TABLET (TRUSTED ZONE)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  DPC         │  │  Kiosk       │  │  VpnService  │  │  Gatekeeper    │  │
│  │  (Device     │  │  Launcher    │  │  DNS/SNI     │  │  WebView +     │  │
│  │  Owner)      │  │  (LockTask)  │  │  Firewall    │  │  LiteRT + OCR  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └───────┬────────┘  │
│         │                 │                 │                  │           │
│  ┌──────┴─────────────────┴─────────────────┴──────────────────┴────────┐  │
│  │  HARDWARE KEYSTORE (TEE / StrongBox) — non-exportable signing key   │  │
│  │  WATCHDOG (WorkManager + ForegroundService) — 10-min heartbeat      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
        │  (1) heartbeat only — 6 fields, signed            │  (2) unblock
        │  (3) parent DigiLocker verification (parent only) │      challenge only
        ▼                                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BACKEND (FastAPI) — UNTRUSTED FOR CHILD DATA           │
│  Heartbeat Intake → Dead-Man Evaluator → WhatsApp/SMS Alerting             │
│  Unblock Adjudicator (Cloud AI, ≥98% auto / human queue) → Ed25519 signer │
│  DigiLocker verification (parent) │ Policy store (age-tier profiles)       │
└─────────────────────────────────────────────────────────────────────────────┘
        │ WhatsApp Business API + SMS (breach alerts to parent only)
        ▼
   PARENT'S PHONE (outside the child's device; receives alerts, never child content)
```

Full Mermaid source for this diagram and every data flow is in `docs/data-flow-diagram.md`. That file is the canonical, embeddable version; the ASCII above is a reading aid only.

### 3.2 Component inventory

| ID | Component | Runs where | Language / stack | Owner deliverable |
|---|---|---|---|---|
| C1 | **Device Policy Controller (DPC)** — `DeviceAdminReceiver` + `DevicePolicyManager` | Tablet, system-privileged as Device Owner | Kotlin | Deliverable 2 |
| C2 | **Kiosk Launcher** — `LockTask` mode, custom home | Tablet, default launcher | Kotlin | Deliverable 2 |
| C3 | **VpnService DNS/SNI Firewall** — always-on, per-app, no DPI for allowlisted DRM | Tablet, `VpnService` | Kotlin | Deliverable 2 |
| C4 | **Gatekeeper WebView** — custom locked-down `WebView` browser, content interceptor | Tablet | Kotlin + `WebView` | Deliverable 3 |
| C5 | **LiteRT / MediaPipe Safety Classifier** — quantized, multilingual, < 300 MB | Tablet, volatile RAM only | Kotlin + LiteRT (int8) | Deliverable 3 |
| C6 | **OCR Screen-Guard** — low-power periodic OCR of unverified app screens | Tablet, volatile RAM only | Kotlin + ML Kit / LiteRT OCR (on-device) | Deliverable 3 |
| C7 | **Hardware Keystore & Ed25519 Policy Verifier** | Tablet, TEE / StrongBox | Kotlin + Android Keystore | Deliverable 4 |
| C8 | **Watchdog** — `WorkManager` + `ForegroundService`, heartbeat signing + offline cache | Tablet | Kotlin | Deliverable 4 |
| C9 | **Backend API** — FastAPI: heartbeat intake, dead-man evaluator, adjudicator, token signer, alerting | Cloud | Python FastAPI | Deliverable 5 |
| C10 | **Cloud AI Safety Adjudicator** | Cloud (backend) | Backend service, model TBD in Deliverable 5 | Deliverable 5 |
| C11 | **DigiLocker Integration** — parent OAuth / virtual-token verification | Cloud (backend) + parent flow | OAuth 2.0, DigiLocker APIs | Deliverable 5 |
| C12 | **Alerting** — WhatsApp Business API + SMS | Cloud (backend) | Provider APIs, credentials via env only | Deliverable 5 |
| C13 | **Human Support Queue** | Cloud / ops tooling | Human workflow, not code in MVP repo | Deliverable 5 (API + queue schema) |

No other component may send, receive, store, or process child data. If a new component is added, it must be added to this table and to the data-flow diagram first.

### 3.3 Key Android APIs (normative for Deliverable 2)

These are the APIs the DPC **must** use. Using a weaker equivalent is a defect.

| Function | API / constant | Notes |
|---|---|---|
| Device Owner provisioning | `DevicePolicyManager.ACTION_PROVISION_MANAGED_DEVICE`, QR payload (`EXTRA_PROVISIONING_*`) | MVP path; ZTE uses the same DPC via zero-touch config |
| Kiosk / LockTask | `DevicePolicyManager.setLockTaskPackages()`, `startLockTask()` | Launcher + Gatekeeper WebView + allowlisted apps only |
| Safe Mode block | `UserManager.DISALLOW_SAFE_BOOT` via `addUserRestriction()` | Set at provisioning; re-asserted on every boot by the DPC |
| ADB / USB debugging block | `DISALLOW_DEBUGGING_FEATURES` | Also block `DISALLOW_USB_FILE_TRANSFER` |
| Factory reset block | `DISALLOW_FACTORY_RESET` | Blocks Settings reset; recovery-mode wipe is *detected* via EFRP / attestation, not prevented (see T-04) |
| Sideload block | `DISALLOW_INSTALL_UNKNOWN_SOURCES`, `DISALLOW_INSTALL_APPS` (except via DPC-managed install) | No third-party APKs, ever |
| Split-screen / multi-window block | `DISALLOW_CREATE_WINDOWS` where applicable + launcher policy; `setLockTaskFeatures()` to disable split-screen in LockTask | Prevents a second app escaping the kiosk beside an allowlisted app |
| Launcher lock | `setDefaultLauncher()` / `addPersistentPreferredActivity()` for the Kiosk Launcher | No unauthorised launcher can become default |
| UPI / financial block | Blocklist by package: `com.google.android.apps.nbu.paisa.user` (GPay), `com.phonepe.app`, `com.paytm.app`, `in.org.npci.upiapp` (BHIM), plus Play billing via `DISALLOW_CONFIG_BILLING` / Play Store restrictions | Package list is a signed policy, not a hard-coded list in the app; see `age-tier-policies.md` |
| SMS / OTP block | `DISALLOW_SMS`, suppress SMS OTP notifications via `NotificationListenerService` policy + block messaging apps | The child must never see an OTP. OTPs are a parent-channel only. |
| SIM / APN block | `DISALLOW_CONFIG_MOBILE_NETWORKS`, `DISALLOW_CONFIG_TETHERING` | SIM may be present for data; settings are locked |
| Nearby streaming block | `setNearbyAppStreamingPolicy()` / `setNearbyNotificationStreamingPolicy()` (`NEARBY_STREAMING_DISABLED`) — API 33+; on API 31–32 enforce via package + notification policy | Blocks cross-device app/notification streaming |
| Play Store billing | Managed Google Play in DO mode; billing disabled by policy; no in-app purchases | Installs only via DPC allowlist |
| Keystore | `KeyGenParameterSpec` with `setIsStrongBoxBacked(true)` (fallback TEE), `PURPOSE_SIGN`, `DIGEST_SHA256`, `setUserAuthenticationRequired(false)` for the watchdog key (no biometric gate on a child's device) | Key is non-exportable; attestation via `KeyAttestation` |
| VpnService | `VpnService.Builder`, always-on via `setAlwaysOnVpnPackage()` (DO can set its own VPN as always-on) | Must survive reboot; if the VPN dies, traffic is blocked (fail closed) |
| WorkManager | `PeriodicWorkRequest` (15-min minimum — see §4.8 note) + `ForegroundService` for the 10-min heartbeat | See §4.8 for how the 10-min cadence is actually achieved |

> **WorkManager note (important):** `PeriodicWorkRequest` has a 15-minute minimum interval on Android. The 10-minute heartbeat cadence in the spec is therefore implemented as a **ForegroundService with its own timer** (the authoritative heartbeat sender), with WorkManager as a *resurrection* mechanism (re-start the service if killed, on boot, on network change). Deliverable 4 must implement this split and document it; a naive `PeriodicWorkRequest(10 min)` will silently be clamped to 15 min and will fail the dead-man timing test.

---

## 4. Component Deep Dive

### 4.1 C1 — Device Policy Controller (DPC)

**Responsibility:** Own the device. Apply and re-assert every user restriction on every boot. Own the policy store (age tier, allowlist, blocklist, backend public key). Own install/uninstall of allowlisted apps (Managed Google Play only). Own un-enrolment — which is *not* a local operation (see §4.1.3).

**Must do:**
- Register as `DeviceAdminReceiver`; become Device Owner via QR provisioning.
- On `BOOT_COMPLETED` and on every DPC start: re-apply *all* restrictions in §3.3, re-assert the default launcher, re-assert the always-on VPN, re-assert LockTask packages. Do not assume a restriction set once stays set.
- Store policy as a **signed policy blob** (Ed25519, verified with the pinned backend public key, §4.7). An unsigned or stale policy is rejected; the last known good policy stays in force (fail closed, not fail open).
- Expose no UI for changing policy on the device. The DPC has no settings screen reachable by the child. Parent changes go through the backend + Human Support flow (§4.9).

**Must not do:**
- Log browsing, app usage, search, or screen content — not locally, not to the backend. Local counters are anonymous aggregates only (e.g. "blocked requests in the last hour: N"), with no URL, package, or timestamp that can be joined to a child.
- Accept a policy update over an unauthenticated channel.

**Un-enrolment (C1.3):** There is no local "remove Device Owner" path for the child or for a parent on the device. Un-enrolment is a Human Support request after DigiLocker re-verification (§4.9, path 2). The backend issues a signed un-enrolment token; the DPC verifies it (§4.7) and only then calls `clearDeviceOwnerApp()` / factory-resets via policy. This is deliberate: a local un-enrolment button is a bypass.

### 4.2 C2 — Kiosk Launcher (LockTask)

**Responsibility:** Be the only home screen. Show only allowlisted apps for the active age tier. Show no settings, no Play Store, no browser other than the Gatekeeper WebView, no widgets that can launch a hidden activity.

**Must do:**
- Be set as the default launcher and the only LockTask package set (plus the Gatekeeper WebView and allowlisted apps).
- Hide the status bar / quick settings where the platform allows in LockTask; block long-press / recents escape routes.
- Render the age-tier name and a single, child-safe "Ask a parent" affordance that *only* opens the unblock-request flow (§4.9) — it does not open settings, a browser, or a message composer with free text.
- On any crash, restart into LockTask immediately. A crashed launcher must never drop the user to the stock launcher.

**Must not do:**
- Show notifications from blocked apps. Notification access is restricted to the DPC / watchdog only.
- Allow app shortcuts, widgets, or deep links that bypass the Gatekeeper.

### 4.3 C3 — VpnService DNS/SNI Firewall

**Responsibility:** Be the network choke point. Every packet from every app — including allowlisted apps and their in-app WebViews — goes through this service. It is always-on and fail-closed.

**Rules (in order):**
1. **Allowlist bypass (no DPI, firewall still applies):** If the UID belongs to a signature-verified allowlisted EdTech app (PW / Physics Wallah, NCERT / DIKSHA, Khan Academy, Unacademy, BYJU'S / Aakash, YouTube Kids) *and* the destination is on that app's signed CDN/domain list, allow the connection without content inspection. This preserves DRM video playback and battery. The firewall still enforces that the destination is on the list — a allowlisted app talking to an unlisted domain is blocked.
2. **Gatekeeper WebView traffic:** All non-allowlisted web traffic is routed *exclusively* through the Gatekeeper WebView (C4). Direct browser / WebView traffic from any other app is blocked.
3. **DNS/SNI filtering:** Block DNS queries and TLS SNI for domains not on the age-tier allowlist or on the blocklist. Block DNS-over-HTTPS (DoH) endpoints that would bypass local DNS filtering. Block known VPN / proxy / DNS-tunnelling destinations.
4. **Block by default:** Anything not explicitly allowed is blocked. There is no "allow all, block bad" mode.

**Failure mode:** If the `VpnService` is stopped, killed, or fails to start, the DPC must (a) attempt restart, (b) if restart fails, block network via policy and show a child-safe "offline" state in the launcher. The device must never silently fall back to unfiltered network.

**What it is not:** It is *not* DPI for DRM streams (§10). It sees DNS names and SNI, not decrypted video payloads. It does not MITM TLS, does not install a CA, and does not decrypt HTTPS. Content inspection happens in the Gatekeeper WebView (C4/C5), where the page is rendered locally — not by intercepting TLS.

### 4.4 C4 — Gatekeeper WebView (the only browser)

**Responsibility:** Be the only way to reach the non-allowlisted web. Every URL the child can open goes through this component.

**Must do:**
- Use a locked-down `WebView`: JavaScript only where the age-tier policy allows it, no file access (`setAllowFileAccess(false)`), no geolocation, no camera/mic, no downloads outside the allowlist, no `intent:` / custom-scheme navigation that can launch another app.
- Intercept every navigation in `shouldOverrideUrlLoading()` and every resource in `shouldInterceptRequest()`: check the URL against the allowlist → if not allowlisted, send the URL (locally, in RAM) to C5 for classification → allow only on an allow verdict.
- Enforce in-app containment: any `WebView` inside an allowlisted app is still subject to C3 (DNS/SNI) *and* cannot navigate to a non-allowlisted domain. An allowlisted app cannot become a back-door browser (see T-05).
- Purge all page content, DOM, and classification inputs from RAM immediately after the verdict. No history is written to disk. No cache of visited pages is retained beyond the WebView's in-memory session, which is cleared on close.

**Must not do:**
- Offer an address bar that accepts arbitrary search queries that are sent to a cloud search engine. Search, where allowed by age tier, is via an allowlisted, child-safe search provider only, and the query itself is never logged or sent to Aegis backend.
- Open external apps via deep links.

### 4.5 C5 — LiteRT / MediaPipe Safety Classifier

**Responsibility:** Classify text and images locally, in volatile RAM, against the active age-tier rubric, for anything not on the cryptographic allowlist.

**Constraints (hard):**
- Total gatekeeper RAM < 300 MB (C4 + C5 + C6 combined). Use quantized int8 LiteRT models only. One model instance per modality; no parallel model loading.
- 100% offline. No model download at runtime from an unauthenticated source; models ship in the APK / are delivered via signed policy update only.
- Multilingual: English, Hindi, Hinglish (Romanized Hindi), Telugu, Tamil, and major Indian regional languages. Hinglish is a first-class input, not an edge case — Romanized Hindi must be normalised before classification.
- Probabilistic output: a score + a verdict (allow / block / escalate-to-human-review-via-unblock-flow). There is no "99% safe" that overrides the allowlist or the firewall.

**Inputs (local only):** Rendered page text (from C4), image frames (from C4, sampled), OCR text (from C6). **Outputs:** A verdict in RAM. **Retention:** None. Inputs are purged immediately after the verdict (explicit `clear()` / zeroing where the API allows; no disk write, no log line containing content).

**Age-tier rubrics:** The classifier is configured per age tier (see `docs/age-tier-policies.md`). A page allowed for 16–17 may be blocked for 5–8. The rubric is part of the signed policy blob, not hard-coded in the app.

### 4.6 C6 — OCR Screen-Guard

**Responsibility:** Periodically check what is actually on screen in *unverified* app screens (apps that are allowlisted but whose content is user-generated or not fully trusted), to catch content that bypassed URL filtering — e.g. text rendered inside an app, images, or a WebView that loaded from a cached / embedded source.

**Constraints:**
- Low-power, low-frequency: sampled checks, not continuous screen recording. No screenshots are saved, transmitted, or retained. OCR runs on an in-memory bitmap that is discarded immediately after classification.
- Only for unverified screens. Signature-verified EdTech video playback (DRM) is *not* OCR'd frame-by-frame — that would break DRM and drain battery. See §10.
- OCR text is fed to C5 (same purge rule) and never leaves RAM.
- OCR evasion is a known residual risk (see T-09): stylised fonts, images-as-text, rapid scrolling. Mitigation is sampling + the firewall + the allowlist, not OCR alone.

### 4.7 C7 — Hardware Keystore & Ed25519 Policy Verifier

**Responsibility:** Give the device an identity that cannot be copied, and give the device a way to trust the backend without trusting the network.

**Key generation (at provisioning, once):**
- Generate an Ed25519 (or, if the Keystore provider requires it, an EC P-256) signing key with `KeyGenParameterSpec`: `setIsStrongBoxBacked(true)` if StrongBox is present, else TEE; `PURPOSE_SIGN`, `DIGEST_SHA256`, non-exportable, no user authentication required (see §3.3).
- Generate a Keystore attestation certificate chain at provisioning and send *only the attestation* (not the key) to the backend for binding `device_id` ↔ public key. The private key never leaves the TEE / StrongBox.
- Store the backend's Ed25519 public key (pinned at provisioning, via the QR payload / first-sync over a trusted network) in the DPC's private storage. This key verifies (a) policy blobs, (b) 24-hour unblock tokens, (c) un-enrolment tokens.

**Verification (offline, on every use):**
- Verify an unblock token: check Ed25519 signature, check `resource` (exact URL or package ID) matches the request, check `age_tier` matches, check `expiry` (24 h from issuance) has not passed, check the token has not already been used for a *different* resource. One token = one resource = 24 h. No replay to a different URL.
- Verify a policy blob: signature + version monotonicity (a policy with a lower version than the installed one is rejected — prevents rollback).
- If verification fails, deny. Log only an anonymous counter.

**Key compromise / rotation:** If attestation fails or `boot_count` resets unexpectedly, the backend treats the device as untrusted (§5, §8 T-07/T-15) and the DPC must re-attest on next online sync before any new unblock token is honoured.

### 4.8 C8 — Watchdog (WorkManager + ForegroundService)

**Responsibility:** Prove the device is alive, untampered, and still enforcing policy — every 10 minutes, even offline.

**Heartbeat packet (exact schema — nothing else may be added without an architecture change):**

```json
{
  "device_id": "aegis-dev-<opaque-id>",
  "keystore_signature": "<Ed25519 signature over the canonical heartbeat bytes>",
  "battery_pct": 87,
  "network_state": "wifi|cellular|offline",
  "boot_count": 42,
  "timestamp": "2026-11-25T14:10:00Z"
}
```

| Field | Why it is allowed | Why it is not child PII |
|---|---|---|
| `device_id` | Opaque, random at provisioning; not the IMEI, serial, or advertising ID | Cannot be joined to a child's name, browsing, or location without the backend's parent-binding table, which is parent data |
| `keystore_signature` | Proves the heartbeat came from the hardware key | A signature over the packet, not content |
| `battery_pct` | Dead-man logic needs it (graceful shutdown vs. abrupt stop) | A number |
| `network_state` | Dead-man logic needs it (offline vs. online-but-silent) | `wifi` / `cellular` / `offline` — no SSID, no IP, no cell ID |
| `boot_count` | Tamper detection (unexpected reset) | A counter |
| `timestamp` | Ordering, replay protection | A time |

**No location, no IP address, no SSID, no app list, no URL, no screenshot, no usage counter that names an app.** If a future requirement asks for any of those, it is a DPDP review, not a code change.

**Offline resilience:** If offline, sign the heartbeat and append it to an encrypted local cache (EncryptedSharedPreferences / EncryptedFile, key in Keystore). On reconnect, batch-sync in timestamp order, oldest first, with a cap (e.g. max 144 cached heartbeats = 24 h at 10-min cadence; older entries are dropped — the gap itself is the signal, not the missing packets). The backend must accept out-of-order / batched heartbeats and evaluate the *gap pattern*, not just the latest packet.

**Cadence implementation:** ForegroundService timer (10 min) is authoritative; WorkManager is the resurrection path (on boot, on service death, on network change). See §3.3 note. The notification for the foreground service is low-priority, child-safe, and non-dismissible by the child.

### 4.9 C9–C13 — Backend, Adjudicator, DigiLocker, Alerting

**Backend (C9, FastAPI):** Stateless API + a policy store + a heartbeat store. It must never store child content. Its tables are: `devices` (device_id, parent_id, age_tier, backend public key binding, enrolment state), `heartbeats` (the 6 fields above, plus server-received time), `unblock_requests` (challenge fields only — see below), `tokens` (issued token ID, resource, age_tier, expiry, status), `parents` (DigiLocker-verified parent record). No table for browsing, app usage, or screen content exists.

**Unblock flow — two tiers, no local override:**

```
Child taps "Ask a parent" on a blocked resource
  → Device builds an Ed25519 challenge: { target_url OR package_id, age_tier }
     (NO free text, NO reason essay, NO child name, NO screenshot)
  → Device signs the challenge with the Keystore key, sends it to /v1/unblock/request
  → Backend verifies the signature + that the device is enrolled + age_tier matches
  → Cloud AI Safety Adjudicator (C10) evaluates ONLY the target + age_tier
       ├─ Tier 1 — Automated: if confidence ≥ 98% that the target is
       │   non-harmful AND strictly age-appropriate (e.g. an unindexed
       │   NCERT article, a coding tool), issue a 24-hour, single-resource
       │   Ed25519 token. Return the token. Device verifies offline (§4.7).
       └─ Tier 2 — Human: permanent unlocks, social / messaging platforms,
           age-tier upgrades, device un-enrolment → AI rejects, request goes
           to the Human Support Queue. A human reviews ONLY after the parent
           re-verifies via DigiLocker. The human never sees child content —
           they see the target + age_tier + parent verification status.
  → Token is verified on-device; the resource is allowed for 24 h only,
     then the allow expires automatically. No renewal without a new request.
```

**Prompt-injection defence (normative):** The unblock request has *no free-text field at all* — in the API schema, in the device UI, and in the backend. A child (or a malicious page) cannot smuggle an instruction, a persuasive essay, or a jailbreak into the adjudicator, because there is no channel for it. The adjudicator's input is a closed enum + a URL/package ID + an age tier. Any request containing extra fields is rejected with `400` and logged as an anonymous anomaly counter. See T-06.

**DigiLocker (C11):** Parent onboarding *only*. Flow: parent starts onboarding in the parent app / web → OAuth to DigiLocker → DigiLocker returns a virtual token / verified identity assertion (name, DOB-derived adulthood flag, document type — never the full document) → backend verifies the token with DigiLocker, marks the parent as verified-adult, and only then binds a `device_id` to that `parent_id`. A device cannot be bound without a verified adult. Re-verification is required for Tier 2 human escalations and for un-enrolment. DigiLocker credentials are never stored by Aegis; only the verification *result* (verified / not verified, verification timestamp, DigiLocker reference ID) is stored. See `docs/data-flow-diagram.md` sequence 2.

**Alerting (C12):** WhatsApp Business API + SMS to the parent's verified phone number only. Messages contain *no child content* — only a breach category, a device nickname (chosen by the parent, e.g. "Aarav's tablet"), and a timestamp, plus a link to the parent dashboard. See §5 for the exact breach triggers.

---

## 5. Trust Boundaries & Data-Flow Summary

### 5.1 Trust boundaries

| Boundary | Inside (trusted) | Outside (untrusted) | Crossing rule |
|---|---|---|---|
| B1 — Device hardware | TEE / StrongBox, Keystore key, boot chain | Any software that can read RAM / storage without the key | Key never leaves TEE; attestation is the only proof |
| B2 — Device Owner / DPC | DPC, Kiosk Launcher, VpnService, Gatekeeper, Watchdog | All other apps, including allowlisted EdTech apps | Other apps cannot call DPC APIs, cannot stop the VPN, cannot become launcher |
| B3 — Volatile RAM (gatekeeper) | Page text, OCR text, classification inputs | Disk, logs, network, backend | Inputs are purged after the verdict; nothing is written |
| B4 — Device → Backend | Signed heartbeat, signed unblock challenge | Internet, MITM | TLS + Ed25519 signatures; backend verifies signature before acting |
| B5 — Backend → Parent | Breach alerts, token issuance (via device) | WhatsApp / SMS provider, parent's phone | Alerts contain no child content; parent data is DigiLocker-verified |
| B6 — Parent → Backend | DigiLocker verification, Human Support requests | Parent's browser / app | DigiLocker OAuth; re-verification for sensitive actions |

### 5.2 What MAY leave the device (exhaustive — §6 of the data-flow doc is canonical)

| Data | Destination | When | Fields (exact) |
|---|---|---|---|
| Heartbeat | Backend `/v1/heartbeat` | Every 10 min (or batched on reconnect) | `device_id`, `keystore_signature`, `battery_pct`, `network_state`, `boot_count`, `timestamp` |
| Unblock challenge | Backend `/v1/unblock/request` | Only when the child taps "Ask a parent" on a blocked resource | `target_url` **or** `package_id`, `age_tier`, `device_id`, `keystore_signature`, `timestamp` |
| Attestation (provisioning only) | Backend `/v1/enrol/attest` | Once, at provisioning | Keystore attestation certificate chain, `device_id` |
| Parent DigiLocker verification | DigiLocker → Backend | Parent onboarding / re-verification | Parent identity assertion (parent data, not child data) |
| Anonymous counters | Backend `/v1/metrics` (optional, MVP: off by default) | Aggregated, if enabled | e.g. "blocked requests: N in the last hour" — no URL, no package, no child identifier beyond `device_id` |

### 5.3 What NEVER leaves the device

Browsing history, app usage logs, screenshots, search queries, voice inputs, text inputs, page content, OCR text, classification inputs/outputs, location, contacts, photos, files, notification content, or any free-text written by the child. **There is no code path for any of these in Deliverables 2–4, and the backend has no endpoint that accepts them.** If a future feature needs any of them, it requires a new architecture document and a DPDP review — not a pull request.

The full Mermaid data-flow diagram proving this — with every arrow labelled and every store marked "local only" or "backend, no child content" — is in `docs/data-flow-diagram.md`.

---

## 6. Policy Enforcement Points

| Enforcement point | Where | What it enforces | If it fails |
|---|---|---|---|
| QR provisioning | Setup wizard | Device Owner, restrictions, launcher, VPN | Enrolment aborts; device stays unprovisioned |
| Boot | DPC `BOOT_COMPLETED` | Re-assert restrictions, launcher, VPN, LockTask | Device stays locked; watchdog alerts on repeated boot-loop |
| Launcher | Kiosk Launcher | Only allowlisted apps visible | Launcher restarts into LockTask |
| Network | VpnService | DNS/SNI allowlist, no DoH bypass, no direct browser | Network blocked (fail closed) |
| Web | Gatekeeper WebView + LiteRT | URL allowlist, content classification | Page blocked |
| Screen | OCR Screen-Guard | Unverified app screens | App screen blocked / app closed to launcher |
| Install | DPC / Managed Play | Only allowlisted packages | Install rejected |
| Unblock | Ed25519 verifier (C7) | Token signature, resource, tier, expiry | Request denied |
| Heartbeat | Watchdog (C8) + Backend evaluator | Liveness, tamper | Breach alert (§7) |

---

## 7. Dead-Man / Breach Logic (Backend)

The backend evaluates heartbeats with **false-positive awareness**. A missing heartbeat is not, by itself, a breach.

**Suppress an alert when:**
- The last heartbeat before the gap had `battery_pct <= 5%` (graceful low-battery shutdown), *or*
- The gap is brief (configurable; MVP default: < 30 min) and the next heartbeat arrives with a consistent `boot_count` and a valid attestation, *or*
- `network_state` was `offline` in the last heartbeat and the device later batch-syncs cached heartbeats covering the gap.

**Dispatch `CRITICAL_TAMPER_BREACH` (WhatsApp Business API + SMS, to the parent only) when ANY of these holds:**

1. **Abrupt silence while powered and online:** Heartbeats stop abruptly while the last known `battery_pct > 15%` **and** the device's IP / network remains active (backend sees continued network activity — e.g. a subsequent unblock request, a TLS handshake, or a heartbeat from a *different* device_id that shares the network fingerprint — or, more conservatively, the backend's last-seen network state was not `offline` and no graceful-shutdown signal was received). MVP rule: no heartbeat for > 30 min, last `battery_pct > 15%`, last `network_state != offline`, no cached-heartbeat batch arrives within the grace window.
2. **Attestation failure / boot-count anomaly:** On reconnect, Keystore attestation fails, *or* `boot_count` resets unexpectedly (decreases, or jumps without a corresponding attestation), *or* the Keystore signature does not verify.
3. **EFRP / recovery wipe:** Enterprise Factory Reset Protection detects a hardware recovery wipe (device reports a wipe / re-enrolment is required on reboot). The device is forced to re-enrol on reboot; the parent is alerted immediately.

**Alert content (exact):** Breach category, parent-chosen device nickname, timestamp (IST), and a link to the parent dashboard. No child content, no URL, no app name, no location.

**Alert delivery:** WhatsApp Business API first, SMS as fallback if WhatsApp delivery fails or is not confirmed within 5 minutes. Both are sent from the backend (C12); the device never sends alerts directly.

---

## 8. Threat Model (STRIDE)

### 8.1 Method

- **Framework:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), applied per component and per trust boundary (§5).
- **Ratings:** Likelihood (Low / Medium / High) and Impact (Low / Medium / High / Critical) are *pre-mitigation* ratings for the MVP threat environment (a determined child, a shared family network, a lost/stolen tablet). Residual risk is *post-mitigation*.
- **Scope:** The child as the primary adversary for bypass; a network attacker for MITM; a thief for physical access; a malicious web page / app for content escape. Nation-state / hardware-lab attacks are out of scope (§10).
- **Tests:** Every threat has a test in the right-hand column. A threat without a passing test is not considered mitigated.

### 8.2 Threat table

| ID | Threat (STRIDE) | Likelihood / Impact | Mitigation (normative) | Residual risk | Test |
|---|---|---|---|---|---|
| T-01 | **Child bypass via Safe Mode** (EoP) — reboot into Safe Mode to disable the DPC / launcher / VPN and use the stock device. | H / Critical | `DISALLOW_SAFE_BOOT` set at provisioning and re-asserted on every boot (§3.3). DPC re-asserts on `BOOT_COMPLETED`. | Low — Safe Mode is blocked by the platform when the restriction is set; residual is a platform bug or a recovery-mode path (see T-04). | Attempt Safe Mode boot on a provisioned device (power + volume-down). Verify the device boots to the kiosk, not Safe Mode. Repeat after a DPC update. |
| T-02 | **Child bypass via ADB / USB debugging** (EoP) — enable ADB, use `adb shell` to disable the DPC, uninstall the launcher, or sideload. | H / Critical | `DISALLOW_DEBUGGING_FEATURES` + `DISALLOW_USB_FILE_TRANSFER`. No developer options reachable in the kiosk. USB debugging is off by default and cannot be enabled without leaving LockTask. | Low — requires physical access + a bypass of the restriction; residual is a pre-provisioning ADB enablement (mitigated by factory-reset-before-provisioning). | Attempt to enable ADB via Settings (unreachable), via USB on a provisioned device, and via `adb devices`. Verify no device is listed / no authorisation prompt appears. |
| T-03 | **Sideload / third-party APK install** (EoP) — install a VPN, a different launcher, a browser, or a bypass tool via APK. | H / High | `DISALLOW_INSTALL_UNKNOWN_SOURCES` + `DISALLOW_INSTALL_APPS` (except DPC-managed installs via Managed Google Play). No file manager that can open APKs is allowlisted. | Low — residual is a vulnerability in an allowlisted app that can install APKs (mitigated by allowlist review + C3 firewall blocking the download domain). | Attempt to install an APK from Downloads, from a WebView download, and via `adb install`. Verify all are rejected. |
| T-04 | **Factory reset via Settings or recovery** (Tampering / EoP) — reset the device to remove the Device Owner. | H / Critical | `DISALLOW_FACTORY_RESET` blocks Settings reset. Recovery-mode wipe cannot be blocked by the platform, so it is *detected*: EFRP forces re-enrolment on reboot, attestation / `boot_count` anomaly triggers `CRITICAL_TAMPER_BREACH` (§7, trigger 3), and the parent is alerted. | Medium — a recovery wipe *does* remove the DO, but the device cannot be used as an open tablet without re-enrolment, and the parent is alerted immediately. This is detection + alerting, not prevention, and must be stated as such to parents. | Attempt Settings reset (blocked). Boot to recovery and wipe (on a test device). Verify (a) the device forces re-enrolment, (b) the backend fires a breach alert, (c) no child data is recoverable from the wiped device. |
| T-05 | **In-app WebView escape** (EoP / Info Disclosure) — an allowlisted app opens a hidden Chromium WebView to a search engine or unapproved domain, bypassing the Gatekeeper. | H / High | C3 firewall applies *even inside allowlisted apps*: DNS/SNI filtering for every UID, including allowlisted UIDs. Gatekeeper is the only browser; other apps' WebViews cannot navigate to non-allowlisted domains. `shouldOverrideUrlLoading` in allowlisted apps is not trusted — the firewall is the enforcement point. | Medium — residual is an app that embeds content via a non-HTTP channel (e.g. cached content, embedded HTML). Mitigated by C6 OCR screen-guard for unverified screens + allowlist review. | In a test allowlisted app, attempt to open `https://www.google.com` and an unapproved domain in an in-app WebView. Verify both are blocked at the firewall and the Gatekeeper is not bypassed. |
| T-06 | **Prompt injection via unblock request** (Spoofing / Tampering) — child (or a malicious page) smuggles a jailbreak / persuasive essay / instruction into the Cloud AI Adjudicator to get a harmful site unblocked. | M / High | **No free-text field exists** — in the UI, in the API schema, or in the backend. The challenge contains only `target_url` / `package_id` + `age_tier` (§4.9). Extra fields are rejected with `400`. The adjudicator's input is a closed schema. The ≥98% confidence threshold + single-resource + 24-h expiry limit blast radius. | Low — residual is a URL that itself encodes an instruction (e.g. a data-URL / query string). Mitigated by URL normalisation + allowlist of URL schemes (`https` only) + adjudicator prompt hardening in Deliverable 5. | Submit an unblock request with a free-text field, with a `prompt` field, and with a data-URL target. Verify all are rejected / normalised. Submit a legitimate NCERT URL and verify it can be auto-approved. |
| T-07 | **MITM on heartbeat / unblock token** (Spoofing / Tampering) — attacker on the family Wi-Fi intercepts, replays, or forges a heartbeat or token to fake liveness or to unlock a resource. | M / High | TLS (pinned where possible) + Ed25519 signatures over canonical bytes + timestamp / nonce for replay protection. Heartbeat signatures are verified with the hardware-bound public key; tokens are verified offline with the pinned backend public key (§4.7). A replayed heartbeat has a stale timestamp and is rejected; a forged token fails signature verification. | Low — residual is a TLS compromise on the network (mitigated by signature verification, which does not depend on TLS). | Intercept traffic with a proxy (test network). Replay a captured heartbeat with a stale timestamp. Forge a token with a wrong key. Verify all are rejected and the device stays locked. |
| T-08 | **Key extraction from the device** (Info Disclosure / Tampering) — attacker extracts the Keystore signing key to forge heartbeats or unblock challenges from another device. | L / Critical | Non-exportable key in TEE / StrongBox; private key never leaves hardware. Attestation binds the key to the device. If attestation fails, the backend distrusts the device (§7, trigger 2). | Low — residual is a hardware / TEE vulnerability (out of scope, §10) or a rooted device (out of scope for MVP; rooted devices must not be provisioned). | Attempt `KeyStore.getEntry()` export, attempt to read the key file, attempt attestation with a tampered key. Verify export fails and attestation fails closed. |
| T-09 | **OCR / classifier evasion** (EoP) — harmful content rendered as an image, in a stylised font, or scrolled rapidly to evade OCR / LiteRT. | H / Medium | Defence in depth: firewall (DNS/SNI) + allowlist + LiteRT (text + vision) + OCR sampling. No single layer is trusted alone. Rapid-scroll / image-as-text is a known residual — the firewall still blocks the *domain*, even if the *content* evades OCR. | Medium — LiteRT is probabilistic (§10). This is the highest residual risk in the content-filtering stack and must be disclosed to parents. | Test with image-as-text, Hinglish in an image, stylised fonts, and rapid scrolling in the Gatekeeper. Measure block rate; document the evasion rate in the MVP validation report. |
| T-10 | **Allowlist / CDN abuse** (Tampering / EoP) — an attacker hosts harmful content on an allowlisted EdTech CDN domain, or compromises an allowlisted app's CDN, to bypass DPI. | M / High | Allowlist is *cryptographic + domain-scoped*: signature verification of the app + a signed, per-app CDN/domain list (not "allow all of `*.cdn.com`"). CDN list is part of the signed policy blob. A domain is removed from the policy by a signed update if abused. DRM bypass is for *video playback*, not for arbitrary web content from that domain — the Gatekeeper still applies to web navigation. | Medium — residual is a compromised CDN serving harmful content that looks like EdTech traffic. Mitigated by per-app domain scoping + rapid policy revocation + OCR screen-guard for unverified screens. | Host test content on a simulated allowlisted CDN domain. Verify (a) video playback works, (b) web navigation to the same domain via the Gatekeeper is still classified, (c) removing the domain from the signed policy blocks it within one policy sync. |
| T-11 | **SIM swap / OTP theft** (Spoofing / Info Disclosure) — child (or a third party) uses the tablet's SIM to receive OTPs, or swaps the SIM to another device to intercept OTPs / UPI. | M / High | UPI apps blocked by package (§3.3); SMS blocked (`DISALLOW_SMS`); SMS OTP notifications suppressed; SIM/APN settings locked (`DISALLOW_CONFIG_MOBILE_NETWORKS`). OTPs are a parent-channel only — the tablet must never display an OTP. Parents are instructed at onboarding to use a SIM that is not used for banking OTPs, or to use an eSIM / data-only SIM where possible. | Medium — residual is a SIM swap at the carrier level (outside Aegis control). Mitigated by the onboarding instruction + the fact that the tablet cannot display or forward an OTP even if one arrives. | Insert a SIM, attempt to open SMS / UPI apps, attempt to receive an OTP. Verify no OTP is visible, no UPI app launches, and SIM settings are unreachable. |
| T-12 | **Parent account takeover** (Spoofing) — attacker takes over the parent's account and un-enrols the device, upgrades the age tier, or approves a harmful unblock. | M / Critical | DigiLocker re-verification for all Tier 2 / sensitive actions (un-enrolment, tier upgrade, permanent unlock). No sensitive action is approved by a password alone. Breach alerts go to the parent's verified phone number, so a takeover that triggers an alert is visible to the real parent. | Medium — residual is a DigiLocker account compromise (outside Aegis control) or a SIM-swap against the parent's phone (see T-11). Mitigated by DigiLocker's own assurance + re-verification per sensitive action, not per session. | Attempt a tier upgrade and an un-enrolment with only a password / session token. Verify both are rejected without DigiLocker re-verification. |
| T-13 | **Backend token forgery** (Spoofing / Tampering) — attacker forges a 24-h unblock token or a policy blob to unlock a resource or downgrade policy. | L / Critical | Tokens and policy blobs are Ed25519-signed with a backend key whose *public* key is pinned on the device at provisioning. The private key is held in the backend's secret store (e.g. a cloud KMS / HSM in production; env-only placeholder in MVP — see §11). Device verifies signature + resource + tier + expiry + version monotonicity offline (§4.7). A forged token fails verification and the resource stays blocked. | Low — residual is compromise of the backend signing key (mitigated by KMS/HSM + key rotation via a signed rotation policy in production; MVP must document the rotation procedure). | Forge a token with a wrong key, with an expired timestamp, for a different resource, and with a lower policy version. Verify all are rejected on-device without a network call. |
| T-14 | **Offline tampering** (Tampering / Repudiation) — child tampers with the device while offline (e.g. changes the clock to extend a token, deletes the heartbeat cache, or modifies the policy store), then reconnects. | M / High | Tokens carry an absolute expiry verified against the backend-issued timestamp, not only the device clock; the device clock is cross-checked on reconnect (if the clock jumped, tokens are re-validated). Heartbeat cache is encrypted (Keystore key) and signed; a deleted cache is itself a gap signal (§7). Policy store is signed; a tampered policy fails verification and the last known good policy stays in force. | Medium — residual is clock manipulation extending a 24-h token by a few hours if the device stays offline. Mitigated by the 24-h limit + the fact that the token is single-resource + the device must reconnect for a new token. | Set the device clock forward 48 h offline, attempt to use an expired token. Delete the heartbeat cache, reconnect, and verify the backend flags the gap. Tamper with the policy file and verify it is rejected. |
| T-15 | **OEM background-service killing** (Denial of Service) — the OEM kills the Watchdog / VpnService in the background, silently disabling the firewall or heartbeat. | M / High | AER devices only for MVP (see §2.1). ForegroundService + WorkManager resurrection + DPC re-assertion on boot. If the VPN dies, fail closed (network blocked). If the watchdog dies, the backend's dead-man logic fires after the grace window (§7) — a killed watchdog *is* a breach signal, not a silent failure. | Medium — residual is an OEM that kills even foreground services aggressively. Mitigated by AER selection + MVP validation on the exact reference hardware. Non-AER devices are out of scope. | On reference hardware, run the device for 24 h with typical use, force-stop the watchdog / VPN via test hooks, and verify (a) the service restarts, (b) network is blocked while the VPN is down, (c) the backend alerts if the heartbeat stops. |
| T-16 | **DNS rebinding / DoH bypass / proxy / VPN app** (EoP) — child uses DoH, a proxy, or a VPN app to bypass DNS filtering. | M / High | Block known DoH endpoints, block proxy / VPN apps by package (not allowlisted), block `DISALLOW_CONFIG_VPN` where the platform allows the DO to do so, and enforce the always-on Aegis VPN — a second VPN cannot be established while the always-on VPN is active. DNS is forced through the firewall's resolver. | Low–Medium — residual is a novel DoH endpoint or a proxy over an allowlisted domain (mitigated by SNI filtering + allowlist scoping). | Attempt to configure DoH in the Gatekeeper, install a VPN app, and configure a proxy. Verify all are blocked / cannot establish a tunnel. |
| T-17 | **Malicious / compromised allowlisted app update** (Tampering) — an EdTech app update introduces a hidden browser, a chat feature, or a data-exfiltration path. | L / High | Allowlist is by package *and* signature *and* version pin where possible; updates are via Managed Google Play only and are reviewed against the allowlist criteria before being approved for the fleet. A new version that adds a WebView / chat feature is blocked until re-reviewed. OCR screen-guard covers unverified screens in the interim. | Medium — residual is a silent update that changes behaviour between reviews. Mitigated by version pinning + the firewall (the new feature's domains are not on the CDN list, so they are blocked). | Simulate an app update that adds a chat domain. Verify the domain is blocked by the firewall even though the app is allowlisted. |

> **Threats T-01 to T-17 are the MVP minimum.** The security reviewer must add a row for any new feature, any new allowlisted app, or any new backend endpoint before it ships.

### 8.3 What STRIDE does not cover

STRIDE covers the device and the backend. It does **not** cover: (a) the parent's own operational security (sharing a DigiLocker login with the child — mitigated by onboarding instructions, not code), (b) social engineering of the Human Support Team (mitigated by DigiLocker re-verification per request, not by a support agent's judgement), and (c) the physical security of the parent's phone (which receives breach alerts). These are documented as residual risks in the DPDP checklist (`docs/dpdp-compliance-checklist.md`).

---

## 9. Sequence Diagrams

The five normative sequence diagrams are in `docs/data-flow-diagram.md` (§3), in Mermaid, embeddable in the repo and in the parent dashboard:

1. **QR provisioning** — factory-reset → QR scan → DO provisioning → restrictions → Kiosk LockTask → Keystore key generation → first heartbeat.
2. **DigiLocker onboarding** — parent OAuth → verification → device binding.
3. **Unblock request** — child taps "Ask a parent" → Ed25519 challenge → Cloud AI (≥98%) → 24-h token *or* Human Support queue.
4. **Heartbeat + breach alert** — 10-min heartbeat → dead-man evaluator → `CRITICAL_TAMPER_BREACH` via WhatsApp + SMS.
5. **Offline heartbeat replay** — offline caching → batch-sync on reconnect → gap evaluation.

Do not duplicate these diagrams here. If a sequence changes, change it in `data-flow-diagram.md` and update the traceability table in §12.

---

## 10. Non-Goals & Limitations (explicit)

| # | Limitation | Consequence for parents / MVP validation |
|---|---|---|
| N1 | **No DPI for DRM allowlisted apps** | Video streams from PW, Khan Academy, YouTube Kids, etc. are not content-inspected packet-by-packet. The firewall enforces the *domain* and the *app signature*; the Gatekeeper + OCR cover web navigation and unverified screens. A harmful video *inside* an allowlisted app's own player is a residual risk (see T-10). |
| N2 | **No guarantee against hardware-level exploits** | Bootloader unlock, TEE vulnerability, or a hardware lab attack can bypass the DO. These are out of scope for MVP. The mitigation is *detection* (attestation, boot-count, EFRP) + alerting, not prevention. |
| N3 | **LiteRT is probabilistic, not 100%** | The classifier will have false positives (blocking a legitimate page) and false negatives (missing harmful content), especially in Hinglish, Romanized Hindi, and image-as-text. The unblock flow exists for false positives; the firewall + allowlist exist for false negatives. The MVP validation report must measure and publish the block / false-positive rate per language. |
| N4 | **No location tracking, no screen recording, no message reading** | By design (DPDP). Aegis cannot tell a parent where the tablet is or what the child typed. If a parent asks for this, the answer is "not in the MVP, and not without a DPDP review." |
| N5 | **No iOS, no phones, no non-AER devices in MVP** | See §2.1. Supporting another OEM skin requires a separate validation pass for background-service killing (T-15). |
| N6 | **No offline unblock** | An unblock token requires a backend round-trip. Offline, a blocked resource stays blocked until the device reconnects and a token is issued. This is fail-closed by design. |
| N7 | **No parent PIN / local override** | By design (P2). A parent who is offline cannot unlock a resource from the device. The parent must use the parent dashboard / Human Support flow. |
| N8 | **Heartbeat is not real-time** | 10-min cadence + grace window means a breach may take up to ~30–40 min to alert (see §7). This is a detection latency, not a prevention guarantee, and must be stated to parents. |
| N9 | **Human Support is a human process, not an SLA in the MVP** | Tier 2 requests go to a queue. The MVP does not guarantee a response time. The queue schema and the DigiLocker re-verification step are in Deliverable 5; the staffing SLA is an ops decision. |
| N10 | **DigiLocker depends on DigiLocker availability** | If DigiLocker is down, parent onboarding and Tier 2 re-verification cannot complete. Enrolled devices continue to enforce policy offline; no new device can be bound until DigiLocker recovers. |

---

## 11. Operational Requirements

### 11.1 Secrets & configuration (placeholders only — no real values in the repo)

| Secret / config | Where it lives | How it is provided |
|---|---|---|
| `${DIGILOCKER_CLIENT_ID}` / `${DIGILOCKER_CLIENT_SECRET}` | Backend env only | DigiLocker developer portal; never in the repo, never in the Android app |
| `${BACKEND_ED25519_PRIVATE_KEY}` | Backend secret store (cloud KMS / HSM in production) | Generated once, backed up offline; public key pinned on devices at provisioning |
| `${WHATSAPP_BUSINESS_API_TOKEN}` / `${SMS_PROVIDER_API_KEY}` | Backend env only | WhatsApp Business / SMS provider portal |
| `${BACKEND_BASE_URL}` | DPC config (signed policy) | e.g. `https://api.aegis-kid.example/v1` — placeholder; set per environment |
| `${ADJUDICATOR_MODEL_ID}` | Backend env only | Cloud AI model identifier for Deliverable 5 |

No secret may appear in a Markdown file, a Kotlin file, a test, or a screenshot. CI must fail on a secret-scan hit.

### 11.2 Provisioning checklist (MVP)

1. Factory-reset the tablet. Verify it is unprovisioned and not rooted.
2. Scan the QR code (generated by the backend for the verified parent + age tier).
3. Verify the DPC becomes Device Owner, the Kiosk Launcher is default, and LockTask starts.
4. Verify the Keystore key is generated (StrongBox if present, else TEE) and attestation succeeds.
5. Verify the first heartbeat arrives at the backend and verifies.
6. Verify the firewall blocks a test unapproved domain and the Gatekeeper blocks a test harmful page.
7. Hand the tablet to the child only after steps 1–6 pass.

### 11.3 Zero-Touch readiness

The DPC and policy model are the same for QR and Zero-Touch. Zero-Touch adds: (a) a ZTE config in the reseller portal pointing at the DPC, (b) enrolment without a QR scan on first boot, (c) the same Keystore / attestation / first-heartbeat flow. No code change is required in the DPC for ZTE; the change is in the enrolment *configuration* and in the backend's enrolment endpoint. ZTE is **not** validated in the MVP; it is validated as a separate milestone after QR provisioning passes.

---

## 12. Traceability to Deliverables 2–5

| This document | Implements in |
|---|---|
| §3.3 API table, §4.1–4.3 | Deliverable 2 — DPC, Kiosk Launcher, VpnService firewall |
| §4.4–4.6, age-tier rubrics | Deliverable 3 — Gatekeeper WebView, LiteRT classifier, OCR screen-guard; rubrics in `docs/age-tier-policies.md` |
| §4.7–4.8, §7 | Deliverable 4 — Keystore, Ed25519 verifier, Watchdog, heartbeat cache |
| §4.9, §7, §11 | Deliverable 5 — FastAPI backend, Adjudicator, DigiLocker, WhatsApp/SMS alerting, Human Support queue |
| §5, `docs/data-flow-diagram.md` | Data-flow proof — every data flow must match the Mermaid diagrams |
| §8 | Security test plan — every threat's Test column is a required test case |
| `docs/dpdp-compliance-checklist.md` | DPDP evidence — every checklist row must have an implementation + evidence link |

---

## Appendix A — Glossary

| Term | Meaning |
|---|---|
| AER | Android Enterprise Recommended |
| DPC | Device Policy Controller — the Device Owner app |
| DO | Device Owner — the highest-privilege management mode on Android |
| EFRP | Enterprise Factory Reset Protection |
| LockTask | Android kiosk mode — the device is locked to a set of packages |
| SNI | Server Name Indication — the hostname in a TLS handshake, visible to the firewall without decrypting traffic |
| DPI | Deep Packet Inspection — inspecting packet payloads; *not* done for DRM streams in this MVP |
| LiteRT | Google's on-device AI runtime (formerly TensorFlow Lite) |
| TEE / StrongBox | Trusted Execution Environment / hardware security module on the device |
| DPDP Act | India's Digital Personal Data Protection Act, 2023; full enforcement from 13 May 2027 |
| DigiLocker | Government of India digital document / identity verification service |

## Appendix B — References (normative where noted)

- Android Enterprise — Device Owner provisioning, `DevicePolicyManager` docs (developer.android.com)
- Android Keystore / Key Attestation docs
- LiteRT / MediaPipe on-device ML docs
- DigiLocker API documentation (developer portal — access via `${DIGILOCKER_CLIENT_ID}`)
- DPDP Act, 2023 — see `docs/dpdp-compliance-checklist.md` for the section-by-section mapping
- `docs/data-flow-diagram.md`, `docs/age-tier-policies.md`, `docs/dpdp-compliance-checklist.md`

---

*End of Deliverable 1 — Architecture & Threat Model. Next: Deliverable 2 (DPC & Kiosk Launcher, Kotlin) must implement §3.3 and §4.1–4.3 exactly as specified here.*
