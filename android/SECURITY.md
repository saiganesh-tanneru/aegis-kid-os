# Aegis-Kid OS (India Edition) — Security: Hardware Keystore & Ed25519 Policy Verifier

> **Scope:** Deliverable 4 only — the `com.aegis.kid.security` package
> (`android/app/src/main/java/com/aegis/kid/security/`) and this document.
> Device Owner / kiosk lockdown is Deliverable 2; the LiteRT gatekeeper is
> Deliverable 3; the backend (DigiLocker, adjudicator, alerts) is Deliverable 5.
> This document is the security contract the other deliverables rely on.
>
> **Privacy baseline (DPDP Act, minors under 18):** no browsing history,
> app-usage logs, screenshots, search queries, or voice/text inputs ever
> leave the device. The only data that leaves is (a) a signed heartbeat
> containing exactly `device_id`, `keystore_signature`, `battery_pct`,
> `network_state`, `boot_count`, `timestamp`, and (b) an unblock challenge
> containing exactly `device_id`, `resource`, `age_tier`, `nonce`,
> `timestamp`, `signature`. Both are defined in code, not in prose —
> see `HeartbeatSigner.kt` and `UnblockChallenge.kt`. Anything else
> leaving the device is a bug, not a feature.

## Files

| File | Responsibility |
|---|---|
| `security/HardwareKeystoreManager.kt` | Device identity key: generation, StrongBox/TEE, attestation, purge |
| `security/Ed25519Signer.kt` | Sign heartbeats + unblock challenges with the Keystore private key |
| `security/Ed25519Verifier.kt` | Verify backend tokens offline against the pinned backend public key |
| `security/PolicyToken.kt` | `PolicyToken` + `AgeTier` (5–8, 9–12, 13–15, 16–17); parse + validate |
| `security/UnblockChallenge.kt` | Prompt-injection-proof challenge (no free text, no PII) |
| `security/HeartbeatSigner.kt` | Canonical heartbeat JSON + signing (exact 6 fields only) |
| `security/HeartbeatCache.kt` | Encrypted offline queue, FIFO cap 288, purge-after-ACK |
| `security/AttestationChecker.kt` | Key attestation + `BOOT_COUNT` reset detection |
| `security/WatchdogService.kt` | Foreground service (10-min loop) + WorkManager guard (15-min) |

---

## 1. Key lifecycle

### 1.1 Generation (provisioning, Device Owner QR flow)

```
Provisioning (QR / Zero-Touch)
  └─ backend issues attestation challenge (opaque nonce, NOT child PII)
  └─ HardwareKeystoreManager.getOrCreateDeviceKey(challenge)
       ├─ try Ed25519, StrongBox          (API 33+, if StrongBox present)
       ├─ try Ed25519, TEE                (API 33+, StrongBox absent/failed)
       ├─ try EC P-256, StrongBox         (API < 33, or Ed25519 rejected)
       └─ try EC P-256, TEE               (last resort)
  └─ public key (Base64, X.509) registered with backend, bound to device_id
  └─ attestation chain stored by backend for later verification
```

- **Alias:** `aegis_device_key`. One key per device, for the life of the enrollment.
- **Non-exportable:** AndroidKeyStore keys cannot be exported by design.
  There is no export function in this package, no key file, no backup.
  `getPrivateKey()` returns a Keystore *reference* usable only for
  `Signature.initSign()` inside the TEE/StrongBox — the raw bytes are
  never accessible to the app process.
- **No user authentication required** (`setUserAuthenticationRequired(false)`):
  deliberate. The heartbeat runs in the background with nobody present
  to authenticate. The key is protected by hardware + UID isolation +
  the Device Owner lockdown instead. It must only sign heartbeats and
  unblock challenges (enforced by `Ed25519Signer` being reachable only
  through `HeartbeatSigner` / `UnblockChallenge`).
- **Algorithm:** Ed25519 preferred (API 33+). EC P-256 / `SHA256withECDSA`
  is the fallback. Callers must read the live algorithm from
  `HardwareKeystoreManager.getAlgorithm()` — never assume Ed25519.
  The backend learns the algorithm from the registered public key.

### 1.2 StrongBox vs TEE

|  | StrongBox | TEE |
|---|---|---|
| What it is | Dedicated tamper-resistant secure element (e.g. Titan M) | Trusted Execution Environment on the main SoC |
| Requested how | `setIsStrongBoxBacked(true)` | Default when StrongBox is unavailable |
| Availability | Flagship / some mid-range; **not guaranteed on budget AER tablets** | All Android 8+ AER devices |
| Failure mode | `StrongBoxUnavailableException` → **guarded fallback to TEE** (never bricks provisioning) | — |
| Trust level | Highest; survives SoC compromise better | Hardware-backed; sufficient for MVP threat model |

**Rule:** never claim StrongBox without evidence. `resolveOrigin()` reads
`KeyInfo.securityLevel` (API 31+) and reports `STRONGBOX` / `TEE` /
`SOFTWARE` honestly. Below API 31 it reports `TEE` (AndroidKeyStore keys
are hardware-backed on AER hardware in practice) and the backend weighs
that accordingly. `AttestationChecker` treats a non-hardware origin as
untrusted.

### 1.3 Use

Only two operations ever use the private key, both through `Ed25519Signer.sign()`:

1. **Heartbeat** — `HeartbeatSigner.sign(payload, signer)` over the
   backend canonical JSON (see §6: `battery_pct`, `boot_count`,
   `device_id`, `timestamp`-as-ISO; `network_state` NOT signed).
2. **Unblock challenge** — `UnblockChallenge.build(..., signer)` over
   the backend canonical JSON (see §6: `age_tier`, `nonce`, `resource`
   only; `device_id` / `timestamp` are transport fields, NOT signed).

No other code path may call `Ed25519Signer.sign()` directly. In
particular: never sign WebView content, URLs supplied by a page,
free-text input, or anything a child typed. That is the
prompt-injection defence — the signer has no free-text input to inject into.

### 1.4 Rotation

- **No scheduled rotation in the MVP.** Rotating a hardware-bound
  device identity key requires re-provisioning (new attestation,
  new backend registration), which on a child's tablet means a
  parent-involved flow. The risk rotation would mitigate (long-term
  key compromise) is lower than the risk it introduces (bricked
  devices, lost heartbeat continuity) at MVP scale.
- **Rotation events (rotate immediately, via re-provisioning):**
  1. Backend reports the device public key as compromised / revoked.
  2. `AttestationChecker` reports a boot-count reset or attestation failure.
  3. Device is transferred to a different child / age tier changes
     *and* the backend requires a fresh identity (policy decision, not automatic).
- Rotation = `purgeOnUnenrollment()` + full Device Owner re-provisioning
  with a fresh attestation challenge. There is no in-place re-key API.

### 1.5 Revocation

Revocation is **backend-side**: the backend marks the registered public
key revoked and thereafter rejects every heartbeat and challenge signed
by it. The device cannot revoke itself (a tampered device would simply
not revoke itself). On revocation the backend:

1. Rejects heartbeats → dead-man logic fires (see §4).
2. Rejects unblock challenges → no tokens are issued.
3. Alerts the parent via WhatsApp Business API + SMS (Deliverable 5).
4. Queues the device for Human Support re-verification (DigiLocker)
   and re-provisioning.

### 1.6 Purge on unenrollment

`HardwareKeystoreManager.purgeOnUnenrollment(cache)`:

- Deletes the Keystore entry (`aegis_device_key`).
- Clears the `HeartbeatCache` (no replayable signed heartbeats survive).
- Is called **only** from the Device Owner unenrollment flow, after
  DigiLocker parent re-verification + Human Support approval. There is
  no on-device button, PIN, or settings path that triggers it — a child
  must not be able to unenroll the device, and a parent must not be
  able to do it silently without the backend knowing.

---

## 2. Token verification flow (offline)

A token is a **time-bound, single-resource** grant from the Cloud AI
Safety Adjudicator (auto-issue, 24 h) or the Human Support Team
(capped at 7 days by policy). Verification works with **no network**.

```mermaid
flowchart TD
    A[Child requests blocked resource] --> B[UnblockChallenge.build\ndeviceId + resource + ageTier\n+ nonce + timestamp\nNO free text, NO PII]
    B --> C[Ed25519Signer signs challenge\nwith Keystore device key]
    C --> D[Challenge sent to Cloud AI\nSafety Adjudicator]
    D --> E{AI verdict >= 98%\nnon-harmful + age-appropriate?}
    E -- No --> F[Reject: permanent unlocks,\nsocial/messaging, tier upgrades,\nun-enrollment go to Human Support\nqueue after DigiLocker re-verify]
    E -- Yes --> G[Backend signs PolicyToken\ncanonical JSON:\n{"age_tier":...,"expires_at":"<ISO>",\n"nonce":...,"resource":...}\nwith backend Ed25519 key]
    G --> H[Token returned to device]
    H --> I[Ed25519Verifier.verifyToken\noffline, no network]
    I --> J{1. Signature valid vs\npinned backend public key?}
    J -- No --> K[REJECT: fail closed]
    J -- Yes --> L{2. Structural checks:\nexact resource match?\nexact age-tier match?\nnonce unseen?\nnot expired (+5 min skew)?\nlifetime <= 7 days?}
    L -- No --> K
    L -- Yes --> M[ACCEPT: allow ONLY that\nresource for that age tier\nuntil expiry]
    M --> N[Consume nonce:\nrecord in seen-nonce store\nso token cannot replay]
```

### Verification gates (all must pass)

| # | Gate | Where | Notes |
|---|---|---|---|
| 1 | Signature over backend canonical JSON (see §6) | `Ed25519Verifier.verifySignedPayload` | Pinned backend key; placeholder key fails closed |
| 2 | Exact resource binding | `PolicyToken.validate` | No wildcards, no prefix/domain matching |
| 3 | Exact age-tier binding | `PolicyToken.validate` | Token for 9–12 does not work on a 5–8 profile |
| 4 | Expiry, ±5 min clock skew | `PolicyToken.isExpired` | `CLOCK_SKEW_TOLERANCE_SECONDS = 300` |
| 5 | Lifetime ≤ 7 days | `PolicyToken.validate` | Auto-issue is 24 h; anything longer is rejected |
| 6 | Nonce not previously consumed | Caller-supplied `seenNonces` set | Single-use; caller must persist the nonce on accept |

### Backend public key (pinned)

`Ed25519Verifier.PLACEHOLDER_BACKEND_PUBLIC_KEY_BASE64` is literally
`REPLACE_ME_WITH_BACKEND_ED25519_PUBLIC_KEY_BASE64`. It is **not a real
key**. With the placeholder in place, `loadBackendPublicKey()` returns
null and every verification fails closed. Replace it at provisioning
time with the real production key (X.509 / SubjectPublicKeyInfo, Base64),
injected by the provisioning flow — never commit a real key to the repo,
and never fetch it over an unauthenticated channel.

---

## 3. Dead-man heartbeat & tamper detection

### 3.1 Cadence — the WorkManager trap

WorkManager's minimum periodic interval is **15 minutes**; it cannot
run a 10-minute periodic job. The design therefore splits the job:

- **Foreground service** (`WatchdogService`): coroutine loop every
  **10 minutes** — builds, signs, caches, and (if online) flushes.
  `START_STICKY` + kiosk lockdown keep it alive.
- **WorkManager** (`HeartbeatWorker`, 15-min periodic): restart guard
  only. Ensures the service is running after low-memory kills /
  reboots; does not itself send heartbeats.

Claiming "WorkManager sends a 10-minute heartbeat" would be false.
This split is the honest implementation of the 10-minute requirement.

### 3.2 Offline resilience

```
tick (10 min)
 ├─ build HeartbeatPayload (6 fields only)
 ├─ sign with Keystore key  →  if signing fails: retry next tick, NEVER send unsigned
 ├─ HeartbeatCache.enqueue  →  EncryptedSharedPreferences, FIFO cap 288 (48 h)
 ├─ battery <= 5%?  → cache only, no network attempt (graceful-shutdown path)
 ├─ offline?         → cache only
 └─ online?          → flushCache(): send all, remove ONLY after backend ACK
```

### 3.3 Backend breach logic (Deliverable 5; device supplies the signals)

The device never raises a breach alert itself. The backend raises
`CRITICAL_TAMPER_BREACH` (WhatsApp Business API + SMS to parent) when:

1. Heartbeats stop abruptly while `battery_pct > 15%` **and** the
   device's IP/network remains active;
2. Keystore attestation fails, or `boot_count` resets unexpectedly
   on reconnect (`AttestationChecker.detectBootCountReset`);
3. Enterprise Factory Reset Protection (EFRP) reports a hardware
   recovery wipe (device must re-enroll on reboot).

**False-positive suppression (backend):** no alert for a graceful
low-battery shutdown (`battery_pct <= 5%` before disconnect) or for
brief offline gaps (travel / train / Wi-Fi off) — cached heartbeats
arrive in a batch on reconnection and close the gap.

### 3.4 Factory reset / EFRP

- A factory reset wipes the AndroidKeyStore: the device key is gone
  and cannot be recovered. That is by design — a reset device has no
  identity until it re-enrolls.
- With EFRP (Device Owner + factory-reset protection), a reset device
  **must re-enroll on reboot**; it cannot come back as an unmanaged
  device with the old identity. The backend sees the new enrollment
  with no prior key, treats the old key as revoked, and alerts the
  parent that a reset occurred.
- `AttestationChecker` additionally catches the softer case: a
  re-flash / rollback that preserves the app but resets `BOOT_COUNT`.
  A boot-count reset + missing heartbeats is a tamper signal even
  without a full wipe.

---

## 4. Threat notes

| Threat | Mitigation in this deliverable | Residual risk / owner |
|---|---|---|
| Child / attacker extracts the device private key | Non-exportable Keystore key in TEE/StrongBox; no export API anywhere in the package | Physical chip-level attack on a budget tablet — out of MVP scope; StrongBox devices reduce this further |
| Replay of an old signed heartbeat | Heartbeats are timestamped; backend rejects stale timestamps; cache purges on ACK + unenrollment | Backend must enforce the timestamp window (Deliverable 5) |
| Replay of a used unblock token | Single-use nonce, consumed on accept (`seenNonces`) | Caller must persist `seenNonces` durably (EncryptedSharedPreferences); an in-memory-only set loses replays across reboot |
| Forged unblock token | Ed25519 signature vs pinned backend key; placeholder key fails closed | Key replacement at provisioning must be authenticated; a leaked backend *signing* key requires rotation (Deliverable 5 runbook) |
| Prompt injection via unblock request | Challenge has no free-text field by construction; resource is normalised (URL → host+path, query/fragment stripped; package ID regex) | Backend must still treat the resource as untrusted data and never interpolate it into a prompt (Deliverable 5) |
| Token used for a different resource / age tier | Exact-match binding, no wildcards | None in this package; the *enforcement point* (gatekeeper, Deliverable 3) must actually check the token before allowing the resource |
| In-app WebView escapes the allowlist | Out of scope here — Deliverable 3 (`VpnService` DNS/SNI firewall stays active inside allowlisted apps) | This package only guarantees the *token* is sound, not that it is enforced everywhere |
| Attacker kills the watchdog | Foreground service + `START_STICKY` + WorkManager guard + Device Owner lockdown (no force-stop from kiosk) | A determined attacker with physical access + unlocked bootloader can still kill it — that is exactly what the dead-man heartbeat detects (silence = alert) |
| Attacker fakes heartbeats after wiping the device | Wiped device has no key; it cannot sign. Backend rejects unsigned heartbeats | None, provided the backend never accepts an unsigned heartbeat |
| Clock manipulation to extend a token | 5-min skew tolerance only; tokens are capped at 7 days and nonces are single-use | Device clock is set by the network/OS; a rooted device could shift its clock — backend should also check token expiry server-side at issue time and treat very old `timestamp`s as suspicious |
| SafetyNet / Play Integrity spoofing | **SafetyNet is deprecated and is not used.** Play Integrity is a server-side verdict and is not faked here; `AttestationChecker` only reports on-device Keystore attestation + boot count | Do not present a local-only result as a Play Integrity verdict |
| Logging leaks keys / signatures / child data | No full key, signature, token, URL, or heartbeat content is ever logged; only truncated fingerprints (first 8 chars) and counts | Code review must keep this invariant on every new log line |
| Heartbeat cache grows unboundedly | FIFO cap of 288 entries (48 h); oldest dropped first, drop counted in logs | Dropped heartbeats are unrecoverable by design — acceptable, the backend escalates long before 48 h |

### What this package does NOT do (explicit non-goals)

- It does not decide what content is safe (Deliverable 3, LiteRT gatekeeper).
- It does not verify parents (Deliverable 5, DigiLocker).
- It does not send WhatsApp/SMS alerts (Deliverable 5).
- It does not enforce the kiosk lockdown (Deliverable 2, Device Owner DPC).
- It does not contain any network client: `WatchdogService.HeartbeatSender`
  is an injected interface; the default implementation caches everything
  and reports offline, so the watchdog is safe to run before the
  transport is wired.

---

## 5. Manifest / dependency notes (for the app module)

- `androidx.security:security-crypto` — `EncryptedSharedPreferences`
  (`HeartbeatCache`). No plaintext fallback: if encrypted storage is
  unavailable, heartbeats are dropped, never written in the clear.
- `androidx.work:work-runtime-ktx` — `HeartbeatWorker` guard.
- `org.json` (Android built-in) — token / heartbeat JSON. No
  kotlinx.serialization dependency is assumed by this package.
- Permissions / declarations owned by the app manifest, not this file:
  `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`,
  `RECEIVE_BOOT_COMPLETED`, foreground service type `dataSync`,
  `ACCESS_NETWORK_STATE`, `BATTERY_STATS` (via `BatteryManager`, no permission needed for capacity).
- Min SDK assumption: API 26+ for `java.util.Base64` paths used in
  `HardwareKeystoreManager`; Ed25519 Keystore keys require API 33+ and
  fall back to EC P-256 below that. Target AER tablets are Android 12–16+,
  so the fallback path is exercised on Android 12 devices.

---

## 6. Cross-deliverable wire contract (Deliverable 5 backend)

**This section is normative.** The Android code in this package was
aligned to the backend as built (`backend/app/crypto.py`,
`backend/app/models.py`, `backend/app/routers/heartbeat.py`,
`backend/app/routers/unblock.py`). An earlier draft of this package
used pipe-delimited canonical strings (`resource|ageTier|...`); those
would **never verify** against the backend and have been removed.
If the backend changes its canonical form, this package must change
in lock-step — a one-sided change silently breaks every signature.

All signed bytes are `canonical_json`:
`json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)`
— keys sorted alphabetically, no whitespace, UTF-8.

| Flow | Signed bytes (exact) | Transmitted but NOT signed | Android source |
|---|---|---|---|
| Policy token (backend → device) | `{"age_tier":"AGE_5_8","expires_at":"<ISO>","nonce":"...","resource":"..."}` | `issued_at` (in model, not in signed payload) | `PolicyToken.canonicalPayload()` |
| Unblock challenge (device → backend) | `{"age_tier":"AGE_5_8","nonce":"...","resource":"..."}` | `device_id`, `timestamp` (transport only) | `UnblockChallenge.signedPayload()` |
| Heartbeat (device → backend) | `{"battery_pct":87,"boot_count":42,"device_id":"...","timestamp":"<ISO>"}` | `network_state` (transmitted, not signed) | `HeartbeatSigner.canonicalJson()` |

### 6.1 Traps that break verification (read before touching any of these)

1. **Timestamps are ISO strings, not epoch seconds.** The backend
   models declare `timestamp: datetime` / `expires_at: datetime` and
   re-derive signed bytes via `.isoformat()`. Sending an epoch integer
   fails Pydantic validation (heartbeat) or `getLong` parsing (token).
   Android sends whole-second UTC ISO strings (`...+00:00`, no
   microseconds) so the backend's parse-then-reformat round-trips
   byte-identically.
2. **`expires_at` is kept verbatim.** `PolicyToken.expiresAtIso` is
   the exact string the backend signed. Never re-format it from epoch
   seconds: Python `isoformat()` may carry microseconds, and any
   re-formatting changes the signed bytes. Expiry checks parse it
   locally (`parseIsoToEpoch`) but verification uses the verbatim string.
3. **`age_tier` in signatures is the enum NAME** (`"AGE_5_8"`), i.e.
   the backend `AgeTier` enum value — not the display code (`"5-8"`).
   The display code lives only in `AgeTier.code` for UI purposes.
4. **Backend docstrings lie; code governs.** `models.UnblockRequest`
   says the device signature is "over resource|age_tier|nonce" and
   `models.PolicyToken` says "over resource|age_tier|expires_at|nonce".
   The code signs `canonical_json(...)` of the dicts above. If a
   future backend change makes the docstrings true, this package
   must be updated to match — do not "fix" the Android side to match
   a docstring.
5. **`UnblockRequest` has `extra="forbid"`.** The wire JSON must
   contain exactly `device_id`, `resource_url_or_package`, `age_tier`,
   `nonce`, `device_signature` — no `timestamp`, no `reason`, nothing
   else, or the backend returns 422. Freshness is enforced server-side
   by the nonce TTL (15 minutes, `NonceStore`), not by a device timestamp.
6. **Resource length cap is 512** (backend `max_length=512`), not 2048.
   `UnblockChallenge.normaliseResource` enforces it client-side.
7. **`boot_count` must be >= 0** (backend `ge=0`). If
   `Settings.Global.BOOT_COUNT` is unavailable (-1), Android clamps
   the wire value to 0 (`bootCountForWire`). That masks "unknown" as
   "0" — the backend cannot distinguish them, so a boot-count of 0
   must not by itself be treated as a reset (see `AttestationChecker`,
   which keeps the -1 / unknown distinction locally).
8. **Backend heartbeat does not verify attestation.** The heartbeat
   router verifies the device signature only; `attestation_valid` /
   `efrp_wipe_detected` default to `True`/`False` in the model and are
   not checked per-heartbeat. Attestation failure and EFRP detection
   must be wired as separate backend signals (Deliverable 5) — do not
   assume a valid heartbeat signature means attestation passed.

### 6.2 Integration notes / known divergences

- **Two `AgeTier` enums exist** with the same member names
  (`com.aegis.kid.security.AgeTier` here, `com.aegis.kid.gatekeeper.AgeTier`
  in Deliverable 3, which additionally carries classifier thresholds).
  They are in different packages so there is no compile conflict, and
  the names map 1:1 — but the app module should converge on one shared
  `AgeTier` (or an explicit `gatekeeper ↔ security` mapping by name)
  before the gatekeeper enforces tokens, or a token verified here
  cannot be consumed there without a manual conversion.
- **Nonce stores are separate by design.** The backend keeps a
  15-minute server-side nonce store for challenges; the device keeps a
  persistent seen-nonce set for *tokens* (caller-supplied to
  `Ed25519Verifier.verifyToken`). The device-side set must be persisted
  (e.g. EncryptedSharedPreferences) — an in-memory-only set loses
  replays across reboot. No such store is implemented in this package;
  the enforcement point (Deliverable 3 gatekeeper) owns it.
- **Backend server key is ephemeral if unset.** If
  `ED25519_PRIVATE_KEY_B64` is not set, the backend generates a fresh
  key per restart and previously issued tokens stop verifying. That is
  a backend deployment property, not an Android bug — but it is the
  first thing to check if offline verification suddenly fails everywhere.
