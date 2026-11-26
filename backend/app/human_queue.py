"""Human Support Queue.

Escalated requests (permanent unlocks, social/messaging, age-tier
upgrades, device un-enrollment) land here for a human, never for an
auto-approve. Workflow: PENDING -> APPROVED | REJECTED (terminal).

Rules:
- DigiLocker re-verification is REQUIRED before a human may approve
  an escalation (create_escalation raises if digilocker_verified is
  False and the caller enforces it; the route layer enforces it).
- The audit log records structured metadata only: escalation id,
  device id, request type, decision. No child content, no free text.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import db
from .models import Escalation, EscalationCreate, EscalationStatus


def _row_to_escalation(row: dict) -> Escalation:
    return Escalation(
        id=row["id"],
        device_id=row["device_id"],
        resource=row["resource"],
        age_tier=row["age_tier"],
        request_type=row["request_type"],
        status=row["status"],
        digilocker_verified=bool(row["digilocker_verified"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        decided_at=datetime.fromisoformat(row["decided_at"]) if row.get("decided_at") else None,
        decided_by=row.get("decided_by"),
    )


def create_escalation(payload: EscalationCreate) -> Escalation:
    if not payload.digilocker_verified:
        raise ValueError("DigiLocker re-verification is required before escalation")
    esc_id = db.insert_escalation(
        {
            "device_id": payload.device_id,
            "resource": payload.resource,
            "age_tier": payload.age_tier.value,
            "request_type": payload.request_type.value,
            "digilocker_verified": True,
        }
    )
    db.insert_audit_log(
        "escalation_created", payload.device_id,
        {"escalation_id": esc_id, "request_type": payload.request_type.value},
    )
    row = db.get_escalation(esc_id)
    assert row is not None
    return _row_to_escalation(row)


def get_escalation(esc_id: int) -> Escalation | None:
    row = db.get_escalation(esc_id)
    return _row_to_escalation(row) if row else None


def list_escalations(status: EscalationStatus | None = None) -> list[Escalation]:
    rows = db.list_escalations(status.value if status else None)
    return [_row_to_escalation(r) for r in rows]


def decide_escalation(esc_id: int, status: EscalationStatus, decided_by: str) -> Escalation | None:
    """Apply a terminal decision. Returns None if not found / not PENDING."""
    if status == EscalationStatus.PENDING:
        raise ValueError("decision must be APPROVED or REJECTED")
    ok = db.update_escalation_status(esc_id, status.value, decided_by)
    if not ok:
        return None
    row = db.get_escalation(esc_id)
    assert row is not None
    db.insert_audit_log(
        "escalation_decided", row["device_id"],
        {"escalation_id": esc_id, "status": status.value, "decided_by": decided_by},
    )
    return _row_to_escalation(row)
