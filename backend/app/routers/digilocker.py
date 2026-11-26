"""DigiLocker router: GET /api/v1/digilocker/auth-url, POST /api/v1/digilocker/verify."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..digilocker import build_authorization_url, verify_parent
from ..models import DigiLockerVerification, DigiLockerVerifyRequest

router = APIRouter(prefix="/api/v1/digilocker", tags=["digilocker"])


@router.get("/auth-url")
def get_auth_url(state: str = "aegis") -> dict:
    return {"authorization_url": build_authorization_url(state)}


@router.post("/verify", response_model=DigiLockerVerification)
async def verify_digilocker(req: DigiLockerVerifyRequest) -> DigiLockerVerification:
    try:
        result = await verify_parent(req.authorization_code, device_id=req.device_id)
    except Exception as exc:  # noqa: BLE001 - surface as 502, never leak provider internals
        raise HTTPException(status_code=502, detail="DigiLocker verification failed") from exc
    if not result.verified or not result.is_adult:
        raise HTTPException(status_code=403, detail="parent identity / adulthood not verified")
    return result
