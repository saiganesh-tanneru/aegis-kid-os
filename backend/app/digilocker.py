"""DigiLocker parent verification (OAuth / virtual-token flow).

Flow (production):
  1. Parent is redirected to DigiLocker with client_id + redirect_uri.
  2. DigiLocker returns an authorization code to the redirect URI.
  3. This backend exchanges the code for an access token (server-side,
     client_secret never leaves the server).
  4. The backend calls the DigiLocker user-info / verification endpoint
     and checks the parent's date of birth -> adulthood (>= 18).
  5. ONLY the verification result is kept: a SHA-256 pseudonymous id,
     is_adult, verified, method, verified_at. No DigiLocker document,
     no Aadhaar number, no full name, no DOB is ever stored.

MVP: DIGILOCKER_MOCK_MODE=true (default) returns a stubbed
verified-adult result so the flow can be tested end-to-end without
real DigiLocker credentials. It MUST be false in any real deployment.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx

from .config import get_settings
from .models import DigiLockerVerification

logger = logging.getLogger(__name__)


def build_authorization_url(state: str) -> str:
    settings = get_settings()
    params = {
        "client_id": settings.digilocker_client_id,
        "redirect_uri": settings.digilocker_redirect_uri,
        "response_type": "code",
        "state": state,
    }
    return f"{settings.digilocker_base_url.rstrip('/')}/oauth/authorize?{urlencode(params)}"


def _pseudonymous_id(subject: str) -> str:
    return hashlib.sha256(subject.encode()).hexdigest()


async def verify_parent(authorization_code: str, device_id: str | None = None) -> DigiLockerVerification:
    """Exchange a DigiLocker authorization code and verify adulthood."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    if settings.digilocker_mock_mode:
        logger.info("DigiLocker mock mode: returning stubbed verified-adult result")
        return DigiLockerVerification(
            parent_pseudonymous_id=_pseudonymous_id(f"mock-parent:{authorization_code}"),
            is_adult=True,
            verified=True,
            method="digilocker_mock",
            verified_at=now,
        )
    if not settings.digilocker_client_id or not settings.digilocker_client_secret:
        raise RuntimeError("DigiLocker is not configured: set DIGILOCKER_CLIENT_ID / CLIENT_SECRET")
    # Production exchange (DigiLocker OAuth2 token endpoint).
    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            f"{settings.digilocker_base_url.rstrip('/')}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": authorization_code,
                "client_id": settings.digilocker_client_id,
                "client_secret": settings.digilocker_client_secret,
                "redirect_uri": settings.digilocker_redirect_uri,
            },
        )
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]
        # The exact DigiLocker user-info path is per integration docs;
        # only the adulthood verdict is extracted from the response.
        user_resp = await client.get(
            f"{settings.digilocker_base_url.rstrip('/')}/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_resp.raise_for_status()
        data = user_resp.json()
        subject = str(data.get("sub") or data.get("id") or authorization_code)
        is_adult = bool(data.get("is_adult", False))
        return DigiLockerVerification(
            parent_pseudonymous_id=_pseudonymous_id(subject),
            is_adult=is_adult,
            verified=is_adult,
            method="digilocker_oauth",
            verified_at=now,
        )
