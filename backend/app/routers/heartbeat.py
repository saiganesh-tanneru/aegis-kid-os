"""Heartbeat router: POST /api/v1/heartbeat, GET /api/v1/devices/{id}/status."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import db
from ..crypto import heartbeat_payload, verify_device_signature
from ..heartbeat import HeartbeatEvaluator
from ..models import DeviceStatus, Heartbeat

router = APIRouter(prefix="/api/v1", tags=["heartbeat"])


def _evaluator() -> HeartbeatEvaluator:
    return HeartbeatEvaluator()


@router.post("/heartbeat", status_code=200)
def post_heartbeat(hb: Heartbeat) -> dict:
    # 1. Verify the device's Ed25519 signature (Hardware Keystore key).
    public_key = db.get_device_public_key(hb.device_id)
    if not public_key:
        raise HTTPException(status_code=401, detail="unknown device: register at provisioning first")
    message = heartbeat_payload(hb.device_id, hb.battery_pct, hb.boot_count, hb.timestamp)
    if not verify_device_signature(public_key, message, hb.keystore_signature):
        raise HTTPException(status_code=401, detail="invalid device signature")
    # 2. Replay protection on the signature is implicit in the timestamp;
    #    the evaluator then applies the dead-man state machine.
    result = _evaluator().record(hb)
    breach = result["breach"]
    return {
        "stored": True,
        "breach": breach.model_dump(mode="json") if breach else None,
    }


@router.get("/devices/{device_id}/status", response_model=DeviceStatus)
def get_device_status(device_id: str) -> DeviceStatus:
    status = _evaluator().get_status(device_id)
    return DeviceStatus(
        device_id=device_id,
        last_heartbeat_at=status.get("last_heartbeat_at"),
        last_battery_pct=status.get("last_battery_pct"),
        last_network_state=status.get("last_network_state"),
        boot_count=status.get("boot_count"),
        minutes_since_heartbeat=status.get("minutes_since_heartbeat"),
        status=status["status"],
        breach=status.get("breach"),
    )
