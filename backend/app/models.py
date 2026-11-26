"""Pydantic models for the Aegis-Kid OS backend.

DPDP ENFORCEMENT (by construction):
- There is NO field anywhere in this file for browsing history, app
  usage logs, screenshots, search queries, or voice/text inputs.
- Do NOT add such a field. The device must never send them, and this
  backend must never accept or store them.
- Free-text fields are deliberately absent from UnblockRequest: the
  adjudicator accepts ONLY a structured resource + age_tier, so a
  child (or an attacker) cannot smuggle a persuasive essay / prompt
  injection into the cloud adjudicator.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgeTier(str, Enum):
    AGE_5_8 = "AGE_5_8"
    AGE_9_12 = "AGE_9_12"
    AGE_13_15 = "AGE_13_15"
    AGE_16_17 = "AGE_16_17"


class NetworkState(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class BreachType(str, Enum):
    HEARTBEAT_STOPPED = "HEARTBEAT_STOPPED"
    ATTESTATION_FAILED = "ATTESTATION_FAILED"
    BOOT_COUNT_RESET = "BOOT_COUNT_RESET"
    EFRP_WIPE = "EFRP_WIPE"


class EscalationStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class EscalationRequestType(str, Enum):
    PERMANENT_APP_UNLOCK = "PERMANENT_APP_UNLOCK"
    SOCIAL_OR_MESSAGING = "SOCIAL_OR_MESSAGING"
    AGE_TIER_UPGRADE = "AGE_TIER_UPGRADE"
    DEVICE_UNENROLLMENT = "DEVICE_UNENROLLMENT"
    OTHER = "OTHER"


class Heartbeat(BaseModel):
    """Minimal zero-PII dead-man heartbeat, signed by the device Keystore key.

    Only device_id, a signature, battery, network state, boot count and
    a timestamp are transmitted. No location, no app list, no content.
    """

    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., min_length=1, max_length=128)
    keystore_signature: str = Field(..., min_length=1, description="Base64 Ed25519 signature over the canonical heartbeat payload.")
    battery_pct: int = Field(..., ge=0, le=100)
    network_state: NetworkState = NetworkState.UNKNOWN
    boot_count: int = Field(..., ge=0)
    timestamp: datetime
    attestation_valid: bool = True
    efrp_wipe_detected: bool = False


class UnblockRequest(BaseModel):
    """Structured unblock request. NO free-text field, by design.

    The device submits ONLY the target URL/package ID and age_tier,
    plus a nonce and its Ed25519 device signature. Any extra field
    (e.g. a 'reason' / essay) is rejected by extra='forbid'.
    """

    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., min_length=1, max_length=128)
    resource_url_or_package: str = Field(..., min_length=1, max_length=512)
    age_tier: AgeTier
    nonce: str = Field(..., min_length=8, max_length=128)
    device_signature: str = Field(..., min_length=1, description="Base64 Ed25519 signature over resource|age_tier|nonce.")

    @field_validator("resource_url_or_package")
    @classmethod
    def _no_free_text(cls, v: str) -> str:
        # A resource is a URL or an Android package id. It must not look
        # like prose / a prompt-injection essay: reject whitespace-heavy
        # or very long values at the model layer as well as in adjudicator.
        if len(v.split()) > 3:
            raise ValueError("resource must be a URL or package id, not free text")
        return v.strip()


class PolicyToken(BaseModel):
    """Time-bound (24h), single-resource Ed25519 signed token."""

    model_config = ConfigDict(extra="forbid")

    resource: str
    age_tier: AgeTier
    issued_at: datetime
    expires_at: datetime
    nonce: str
    signature: str  # base64 Ed25519 signature over resource|age_tier|expires_at|nonce


class TokenVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: PolicyToken


class DigiLockerVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    authorization_code: str = Field(..., min_length=1)
    device_id: str | None = None


class DigiLockerVerification(BaseModel):
    """Verification RESULT only. No DigiLocker document is ever stored."""

    model_config = ConfigDict(extra="forbid")

    parent_pseudonymous_id: str  # SHA-256 hash of the DigiLocker subject id
    is_adult: bool
    verified: bool
    method: Literal["digilocker_oauth", "digilocker_mock"]
    verified_at: datetime


class BreachAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    device_nickname: str | None = None  # operator-assigned nickname only; no child name
    breach_type: BreachType
    severity: Literal["CRITICAL"] = "CRITICAL"
    detected_at: datetime
    reason: str
    last_battery_pct: int | None = None
    gap_minutes: float | None = None


class EscalationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., min_length=1, max_length=128)
    resource: str = Field(..., min_length=1, max_length=512)
    age_tier: AgeTier
    request_type: EscalationRequestType
    digilocker_verified: bool = False
    # NOTE: no free-text 'reason' field - human review is based on the
    # structured resource + type only, to keep child content out of the queue.


class Escalation(BaseModel):
    id: int
    device_id: str
    resource: str
    age_tier: AgeTier
    request_type: EscalationRequestType
    status: EscalationStatus = EscalationStatus.PENDING
    digilocker_verified: bool = False
    created_at: datetime
    decided_at: datetime | None = None
    decided_by: str | None = None


class EscalationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["APPROVED", "REJECTED"]
    decided_by: str = Field(..., min_length=1, max_length=128)
    digilocker_verified: bool = False


class DeviceRegister(BaseModel):
    """Provisioning-only device registration (Device Owner enrolment).

    In production this endpoint must sit behind provisioning auth.
    It binds a device_id to its Hardware Keystore public key so later
    heartbeats / unblock requests can be signature-verified.
    """

    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., min_length=1, max_length=128)
    public_key_b64: str = Field(..., min_length=1)
    device_nickname: str | None = Field(default=None, max_length=64)


class DeviceStatus(BaseModel):
    device_id: str
    last_heartbeat_at: datetime | None = None
    last_battery_pct: int | None = None
    last_network_state: NetworkState | None = None
    boot_count: int | None = None
    minutes_since_heartbeat: float | None = None
    status: Literal["HEALTHY", "OFFLINE_BRIEF", "GRACEFUL_SHUTDOWN", "CRITICAL_TAMPER_BREACH", "UNKNOWN"]
    breach: BreachAlert | None = None
