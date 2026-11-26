"""Ed25519 signing / verification (PyNaCl).

Two distinct uses - do not conflate them:
1. SERVER tokens: the backend signs 24h single-resource PolicyTokens
   with its own Ed25519 key. Devices verify them offline.
2. DEVICE signatures: a device signs heartbeats / unblock requests
   with its Hardware Keystore (TEE/StrongBox) key. The backend
   verifies them against the public key bound at provisioning.

Replay protection: every device-signed request carries a nonce.
A nonce may be used once, within its TTL (15 minutes). Replayed or
expired nonces are rejected.
"""
from __future__ import annotations

import base64
import json
import logging
import threading
from datetime import datetime, timedelta, timezone

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from .config import get_settings
from .models import AgeTier, PolicyToken

logger = logging.getLogger(__name__)

TOKEN_TTL_HOURS = 24
NONCE_TTL_MINUTES = 15


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def canonical_json(payload: dict) -> bytes:
    """Deterministic JSON used for every signature (sorted keys, no spaces)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


# --- server keypair ------------------------------------------------------
_server_signing_key: SigningKey | None = None


def get_server_signing_key() -> SigningKey:
    global _server_signing_key
    if _server_signing_key is not None:
        return _server_signing_key
    settings = get_settings()
    if settings.ed25519_private_key_b64:
        _server_signing_key = SigningKey(_b64d(settings.ed25519_private_key_b64))
    else:
        logger.warning(
            "ED25519_PRIVATE_KEY_B64 is not set - using an ephemeral server key. "
            "Tokens will NOT verify after restart. Set the env var in production."
        )
        _server_signing_key = SigningKey.generate()
    return _server_signing_key


def get_server_public_key_b64() -> str:
    return _b64e(bytes(get_server_signing_key().verify_key))


def generate_keypair() -> tuple[str, str]:
    """Return (private_seed_b64, public_key_b64) for provisioning / tests."""
    sk = SigningKey.generate()
    return _b64e(bytes(sk)), _b64e(bytes(sk.verify_key))


def sign_bytes(message: bytes, signing_key: SigningKey | None = None) -> str:
    sk = signing_key or get_server_signing_key()
    return _b64e(bytes(sk.sign(message).signature))


# --- PolicyToken (server-issued, 24h, single resource) --------------------
def token_payload(resource: str, age_tier: AgeTier, expires_at: datetime, nonce: str) -> dict:
    return {
        "resource": resource,
        "age_tier": age_tier.value,
        "expires_at": expires_at.isoformat(),
        "nonce": nonce,
    }


def issue_policy_token(
    resource: str, age_tier: AgeTier, nonce: str, now: datetime | None = None
) -> PolicyToken:
    now = now or datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=TOKEN_TTL_HOURS)
    payload = token_payload(resource, age_tier, expires_at, nonce)
    signature = sign_bytes(canonical_json(payload))
    return PolicyToken(
        resource=resource,
        age_tier=age_tier,
        issued_at=now,
        expires_at=expires_at,
        nonce=nonce,
        signature=signature,
    )


def verify_policy_token(token: PolicyToken, now: datetime | None = None) -> bool:
    """True only if the signature is valid AND the token has not expired."""
    now = now or datetime.now(timezone.utc)
    if token.expires_at <= now:
        return False
    payload = token_payload(token.resource, token.age_tier, token.expires_at, token.nonce)
    try:
        get_server_signing_key().verify_key.verify(canonical_json(payload), _b64d(token.signature))
        return True
    except (BadSignatureError, ValueError):
        return False


# --- device signature verification ---------------------------------------
def verify_device_signature(
    public_key_b64: str, message: bytes, signature_b64: str
) -> bool:
    try:
        VerifyKey(_b64d(public_key_b64)).verify(message, _b64d(signature_b64))
        return True
    except (BadSignatureError, ValueError):
        return False


def heartbeat_payload(device_id: str, battery_pct: int, boot_count: int, timestamp: datetime) -> bytes:
    return canonical_json(
        {
            "device_id": device_id,
            "battery_pct": battery_pct,
            "boot_count": boot_count,
            "timestamp": timestamp.isoformat(),
        }
    )


def unblock_payload(resource: str, age_tier: AgeTier, nonce: str) -> bytes:
    return canonical_json(
        {"resource": resource, "age_tier": age_tier.value, "nonce": nonce}
    )


# --- replay-nonce store (in-memory, TTL-bounded) --------------------------
class NonceStore:
    """Single-use nonces. Thread-safe; entries expire after NONCE_TTL_MINUTES."""

    def __init__(self) -> None:
        self._seen: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def check_and_store(self, nonce: str, now: datetime | None = None) -> bool:
        """Return True on first use, False if the nonce was already seen."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            self._purge_expired(now)
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + timedelta(minutes=NONCE_TTL_MINUTES)
            return True

    def _purge_expired(self, now: datetime) -> None:
        expired = [n for n, exp in self._seen.items() if exp <= now]
        for n in expired:
            del self._seen[n]


nonce_store = NonceStore()
