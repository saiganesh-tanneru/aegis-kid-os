"""Support / admin router: device registration + human support queue.

POST /api/v1/support/escalate
GET  /api/v1/support/escalations
GET  /api/v1/support/escalations/{id}
POST /api/v1/support/escalations/{id}/decision
POST /api/v1/devices/register  (provisioning only - protect in production)
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import db
from ..human_queue import create_escalation, decide_escalation, get_escalation, list_escalations
from ..models import DeviceRegister, Escalation, EscalationCreate, EscalationDecision, EscalationStatus

router = APIRouter(prefix="/api/v1", tags=["support"])


@router.post("/devices/register", status_code=201)
def register_device(payload: DeviceRegister) -> dict:
    db.register_device(payload.device_id, payload.public_key_b64, payload.device_nickname)
    return {"registered": True, "device_id": payload.device_id}


@router.post("/support/escalate", response_model=Escalation, status_code=201)
def escalate(payload: EscalationCreate) -> Escalation:
    try:
        return create_escalation(payload)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/support/escalations", response_model=list[Escalation])
def list_all_escalations(status: EscalationStatus | None = None) -> list[Escalation]:
    return list_escalations(status)


@router.get("/support/escalations/{esc_id}", response_model=Escalation)
def get_one_escalation(esc_id: int) -> Escalation:
    esc = get_escalation(esc_id)
    if not esc:
        raise HTTPException(status_code=404, detail="escalation not found")
    return esc


@router.post("/support/escalations/{esc_id}/decision", response_model=Escalation)
def decide(esc_id: int, decision: EscalationDecision) -> Escalation:
    # DigiLocker re-verification is required before a human may approve.
    if decision.status == "APPROVED" and not decision.digilocker_verified:
        raise HTTPException(status_code=403, detail="DigiLocker re-verification required before approval")
    result = decide_escalation(esc_id, EscalationStatus(decision.status), decision.decided_by)
    if result is None:
        raise HTTPException(status_code=404, detail="escalation not found or already decided")
    return result
