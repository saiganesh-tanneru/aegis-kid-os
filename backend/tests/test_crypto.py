"""Tests for Ed25519 tokens, device signatures, and nonce replay."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from nacl.signing import SigningKey

from app.crypto import (
    NonceStore,
    generate_keypair,
    heartbeat_payload,
    issue_policy_token,
    verify_device_signature,
    verify_policy_token,
)
from app.models import AgeTier


def test_token_issue_and_verify_roundtrip():
    token = issue_policy_token("https://ncert.nic.in", AgeTier.AGE_9_12, "nonce-1")
    assert verify_policy_token(token) is True
    # 24h TTL: expires roughly 24h after issue.
    delta = token.expires_at - token.issued_at
    assert timedelta(hours=23, minutes=59) < delta <= timedelta(hours=24, minutes=1)


def test_token_expired_is_rejected():
    past = datetime.now(timezone.utc) - timedelta(hours=25)
    token = issue_policy_token("https://ncert.nic.in", AgeTier.AGE_9_12, "nonce-2", now=past)
    assert verify_policy_token(token) is False


def test_token_tampered_resource_is_rejected():
    token = issue_policy_token("https://ncert.nic.in", AgeTier.AGE_9_12, "nonce-3")
    tampered = token.model_copy(update={"resource": "https://evil.example"})
    assert verify_policy_token(tampered) is False


def test_token_tampered_signature_is_rejected():
    token = issue_policy_token("https://ncert.nic.in", AgeTier.AGE_9_12, "nonce-4")
    tampered = token.model_copy(update={"signature": base64.b64encode(b"\x00" * 64).decode()})
    assert verify_policy_token(tampered) is False


def test_device_signature_verifies_and_wrong_key_fails():
    priv_b64, pub_b64 = generate_keypair()
    sk = SigningKey(base64.b64decode(priv_b64))
    ts = datetime.now(timezone.utc)
    msg = heartbeat_payload("dev-1", 80, 3, ts)
    sig = base64.b64encode(bytes(sk.sign(msg).signature)).decode()
    assert verify_device_signature(pub_b64, msg, sig) is True
    # Wrong key / tampered message must fail.
    _, other_pub = generate_keypair()
    assert verify_device_signature(other_pub, msg, sig) is False
    assert verify_device_signature(pub_b64, b"tampered", sig) is False


def test_nonce_replay_rejected():
    store = NonceStore()
    assert store.check_and_store("n-abc") is True
    assert store.check_and_store("n-abc") is False  # replay
    assert store.check_and_store("n-def") is True
