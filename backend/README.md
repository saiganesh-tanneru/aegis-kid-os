# Aegis-Kid OS (India Edition) — Backend MVP

Central Watchdog, AI Adjudicator & Parent Alert Backend (Python FastAPI).

**Deliverable 5** of the Aegis-Kid OS MVP spec. Android code lives in
`../android/` and architecture docs in `../docs/` — this folder is the
backend only.

## What it does

| Module | Responsibility |
| --- | --- |
| `app/heartbeat.py` | Dead-man heartbeat state machine (false-positive aware) |
| `app/adjudicator.py` | Prompt-injection-hardened Cloud AI Safety Adjudicator |
| `app/crypto.py` | Ed25519 server tokens (24h, single-resource) + device signature verification + nonce replay protection |
| `app/digilocker.py` | DigiLocker parent identity / adulthood verification (OAuth, stubbed in MVP mock mode) |
| `app/alerts.py` | WhatsApp Business API + SMS `CRITICAL_TAMPER_BREACH` alerts, 1/hour rate limit per device |
| `app/human_queue.py` | Human Support Queue (PENDING → APPROVED / REJECTED, DigiLocker re-verification required) |
| `app/db.py` | SQLite persistence (stdlib only) |
| `app/routers/` | FastAPI routers: heartbeat, unblock, digilocker, admin/support |

## DPDP privacy-by-design (read first)

This backend **NEVER** receives, stores, or logs browsing history,
app usage logs, screenshots, search queries, or voice/text inputs
from a child. There is no such field in any model in `app/models.py`
and no such table in `app/db.py`. Do not add one.

- AI inspection / OCR runs on-device; only a structured
  `{resource, age_tier}` pair ever reaches the cloud adjudicator.
- The adjudicator accepts **no free-text field** (`extra="forbid"`),
  so prompt-injection essays cannot reach the LLM.
- The optional LLM hook receives only resource metadata.
- Heartbeats carry only `device_id, signature, battery_pct,
  network_state, boot_count, timestamp` — zero PII.
- DigiLocker: only the verification *result* is kept (SHA-256
  pseudonymous parent id, `is_adult`, `verified`). No document,
  Aadhaar number, name, or DOB is stored.
- Heartbeats are retained 30 days, then purged (`purge_old_heartbeats`).
- Request logs record method + path + status only — never bodies.

## Endpoints

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/health` | Liveness |
| GET | `/` | App info |
| POST | `/api/v1/devices/register` | Provisioning-only: bind `device_id` → Keystore public key |
| POST | `/api/v1/heartbeat` | Ed25519-signed heartbeat; returns breach if any |
| GET | `/api/v1/devices/{id}/status` | Dead-man status (`HEALTHY` / `OFFLINE_BRIEF` / `GRACEFUL_SHUTDOWN` / `CRITICAL_TAMPER_BREACH` / `UNKNOWN`) |
| POST | `/api/v1/unblock/request` | Ed25519 + nonce; auto-approve only at confidence ≥ 0.98 |
| POST | `/api/v1/unblock/verify` | Verify a 24h PolicyToken (offline-verifiable on device too) |
| GET | `/api/v1/digilocker/auth-url` | DigiLocker OAuth authorisation URL |
| POST | `/api/v1/digilocker/verify` | Exchange auth code → adulthood verification |
| POST | `/api/v1/support/escalate` | Human queue; requires `digilocker_verified: true` |
| GET | `/api/v1/support/escalations` | List queue (optional `?status=PENDING`) |
| GET | `/api/v1/support/escalations/{id}` | One escalation |
| POST | `/api/v1/support/escalations/{id}/decision` | APPROVED / REJECTED; approval requires DigiLocker re-verification |

Interactive docs: `http://localhost:8000/docs`

## Dead-man / breach rules

A `CRITICAL_TAMPER_BREACH` fires when:

1. Heartbeats stop abruptly: gap ≥ 30 min **and** last battery > 15%
   **and** last network state was online.
2. Hardware Keystore attestation fails on a heartbeat.
3. `boot_count` resets (new value < highest seen).
4. EFRP wipe flag is set (hardware recovery wipe).

Suppressed (no alert): last battery ≤ 5% (graceful shutdown),
gap < 30 min (brief offline gap), device was offline at last
heartbeat, or battery in the ambiguous 6–15% zone.

## Adjudicator rules

- Auto-approve **only** at confidence ≥ 0.98 for a non-harmful,
  age-appropriate resource (allowlisted Indian EdTech domains /
  packages, e.g. NCERT, DIKSHA, Khan Academy, PW, Scratch, Code.org).
- Social / messaging, UPI / finance, adult / gambling resources →
  **ESCALATE** to the Human Support Queue, never auto-approved.
- Unknown resources → **DENIED** (confidence 0.50, below threshold).
- Full YouTube is denied below age 16–17 (use YouTube Kids).
- Approved tokens are Ed25519-signed, single-resource, 24-hour.

## Quick start

```bash
cd backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in real credentials; never commit .env
uvicorn app.main:app --reload
# open http://localhost:8000/docs
```

Generate a server signing key (do this once, put it in `.env`):

```bash
python -c "import nacl.signing, base64; print(base64.b64encode(bytes(nacl.signing.SigningKey.generate())).decode())"
```

Without `ED25519_PRIVATE_KEY_B64` the server uses an ephemeral key
and logs a warning — tokens will not verify after a restart.

Docker:

```bash
cp .env.example .env
docker compose up --build
```

## Tests

```bash
pytest -q
```

Covers: token issue/verify/expiry/tamper, device signatures,
nonce replay, breach suppression (low battery, brief gap, offline),
breach triggers (abrupt stop, boot-count reset, attestation failure,
EFRP wipe), the ≥ 0.98 auto-approve threshold, social/UPI
escalation, and prompt-injection / free-text rejection.

## Configuration

All settings are env-based — see `.env.example`. No real API keys,
phone numbers, or tokens are stored in this repo. With no WhatsApp /
SMS credentials configured, alert sending is stubbed (logged) rather
than failing. With `DIGILOCKER_MOCK_MODE=true` (default) DigiLocker
verification returns a stubbed verified-adult result; set it to
`false` and supply real credentials for a real deployment.

## Project layout

```
backend/
  README.md  requirements.txt  pyproject.toml  .env.example
  Dockerfile  docker-compose.yml
  app/
    __init__.py  main.py  config.py  models.py  crypto.py
    db.py  heartbeat.py  adjudicator.py  digilocker.py
    alerts.py  human_queue.py  routes.py
    routers/  heartbeat.py  unblock.py  digilocker.py  admin.py
  tests/
    test_crypto.py  test_heartbeat.py  test_adjudicator.py
```
