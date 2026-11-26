"""Unblock router: POST /api/v1/unblock/request, POST /api/v1/unblock/verify."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import db
from ..adjudicator import adjudicate, call_llm_adjudicator
from ..crypto import nonce_store, unblock_payload, verify_device_signature, verify_policy_token
from ..models import PolicyToken, TokenVerifyRequest, UnblockRequest

router = APIRouter(prefix="/api/v1/unblock", tags=["unblock"])


@router.post("/request")
async def request_unblock(req: UnblockRequest) -> dict:
    # 1. Replay protection: nonce must be fresh (single use, 15 min TTL).
    if not nonce_store.check_and_store(req.nonce):
        raise HTTPException(status_code=409, detail="replayed or duplicate nonce")
    # 2. Verify the device's Ed25519 signature over resource|age_tier|nonce.
    public_key = db.get_device_public_key(req.device_id)
    if not public_key:
        raise HTTPException(status_code=401, detail="unknown device: register at provisioning first")
    if not verify_device_signature(
        public_key, unblock_payload(req.resource_url_or_package, req.age_tier, req.nonce), req.device_signature
    ):
        raise HTTPException(status_code=401, detail="invalid device signature")
    # 3. Adjudicate. The LLM hook (if configured) receives ONLY the
    #    resource + age_tier - no child PII, no free text.
    llm_confidence = await call_llm_adjudicator(req.resource_url_or_package, req.age_tier)
    result = adjudicate(req, llm_confidence=llm_confidence)
    if result.decision == "APPROVED" and result.token is not None:
        db.insert_token(
            {
                "nonce": result.token.nonce,
                "resource": result.token.resource,
                "age_tier": result.token.age_tier.value,
                "expires_at": result.token.expires_at.isoformat(),
                "signature": result.token.signature,
                "issued_at": result.token.issued_at.isoformat(),
            }
        )
    return {
        "decision": result.decision,
        "confidence": result.confidence,
        "reason": result.reason,
        "escalate_to": result.escalate_to,
        "token": result.token.model_dump(mode="json") if result.token else None,
    }


@router.post("/verify")
def verify_token(req: TokenVerifyRequest) -> dict:
    token: PolicyToken = req.token
    return {"valid": verify_policy_token(token), "resource": token.resource, "age_tier": token.age_tier}
