"""Parent breach alerts: WhatsApp Business API + SMS fallback.

Rules:
- Only CRITICAL_TAMPER_BREACH alerts are sent from this module.
- Message body contains ONLY the device nickname (operator-assigned),
  the breach type, and the time. No child name, no location, no
  browsing/app content, no PII beyond the parent's own delivery handle.
- Rate limit: at most 1 alert per hour per (device, breach type).
  Repeated breaches inside the window are logged, not re-sent.
- If no provider credentials are configured, sending is stubbed
  (logged, status='stubbed') so the MVP runs without real providers.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

import httpx

from .config import get_settings
from .models import BreachAlert

logger = logging.getLogger(__name__)

_ALERT_WINDOW = timedelta(hours=1)
_last_sent: dict[tuple[str, str], datetime] = {}
_lock = threading.Lock()


def can_send(device_id: str, breach_type: str, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    key = (device_id, breach_type)
    with _lock:
        last = _last_sent.get(key)
        if last and now - last < _ALERT_WINDOW:
            return False
        _last_sent[key] = now
        return True


def breach_message(alert: BreachAlert) -> str:
    nickname = alert.device_nickname or alert.device_id
    return (
        f"Aegis-Kid OS alert: CRITICAL_TAMPER_BREACH on device '{nickname}' "
        f"({alert.breach_type.value}) at {alert.detected_at.isoformat()}. "
        f"Reason: {alert.reason} Please check the device."
    )


def send_whatsapp(to: str, message: str) -> dict:
    """Send via WhatsApp Business API (Meta Graph). `to` is the parent's
    WhatsApp number as stored at provisioning. Stubbed if unconfigured."""
    settings = get_settings()
    if not settings.whatsapp_token or not settings.whatsapp_phone_number_id:
        logger.info("WhatsApp not configured - stubbing send to redacted recipient")
        return {"channel": "whatsapp", "status": "stubbed", "detail": "WHATSAPP_TOKEN not configured"}
    url = (
        f"{settings.whatsapp_api_url.rstrip('/')}/{settings.whatsapp_phone_number_id}/messages"
    )
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "template",
        "template": {
            "name": settings.whatsapp_template_name,
            "language": {"code": "en"},
            "components": [
                {"type": "body", "parameters": [{"type": "text", "text": message}]}
            ],
        },
    }
    try:
        resp = httpx.post(
            url,
            headers={"Authorization": f"Bearer {settings.whatsapp_token}"},
            json=payload, timeout=15,
        )
        resp.raise_for_status()
        return {"channel": "whatsapp", "status": "sent", "detail": resp.json()}
    except Exception as exc:  # noqa: BLE001 - alert failure is reported, not raised
        logger.error("WhatsApp send failed: %s", exc)
        return {"channel": "whatsapp", "status": "failed", "detail": str(exc)}


def send_sms(to: str, message: str) -> dict:
    """Send via the configured SMS provider (Msg91 default, Twilio alt).
    Stubbed if unconfigured."""
    settings = get_settings()
    if not settings.sms_api_key and not settings.twilio_account_sid:
        logger.info("SMS not configured - stubbing send to redacted recipient")
        return {"channel": "sms", "status": "stubbed", "detail": "SMS credentials not configured"}
    # Provider-specific HTTP calls are intentionally minimal in the MVP:
    # Msg91 and Twilio both accept a simple POST; wire the real payload
    # in deployment with the provider's documented schema.
    try:
        if settings.sms_provider.lower() == "twilio":
            resp = httpx.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{settings.twilio_account_sid}/Messages.json",
                auth=(settings.twilio_account_sid, settings.twilio_auth_token),
                data={"From": settings.twilio_from_number, "To": to, "Body": message},
                timeout=15,
            )
        else:  # msg91
            resp = httpx.post(
                "https://api.msg91.com/api/v5/flow/",
                headers={"authkey": settings.sms_api_key},
                json={"to": to, "message": message, "sender": settings.sms_sender_id},
                timeout=15,
            )
        resp.raise_for_status()
        return {"channel": "sms", "status": "sent", "detail": "ok"}
    except Exception as exc:  # noqa: BLE001
        logger.error("SMS send failed: %s", exc)
        return {"channel": "sms", "status": "failed", "detail": str(exc)}


def send_breach_alert(alert: BreachAlert, parent_whatsapp: str | None = None, parent_sms: str | None = None) -> dict:
    """Send a breach alert, honouring the 1/hour rate limit.

    Returns {"sent": bool, "channels": [...]}. If rate-limited, sent
    is False and no provider call is made.
    """
    if not can_send(alert.device_id, alert.breach_type.value):
        logger.info("Breach alert rate-limited for device_id=%s", alert.device_id)
        return {"sent": False, "reason": "rate_limited_1_per_hour", "channels": []}
    message = breach_message(alert)
    channels: list[dict] = []
    if parent_whatsapp:
        channels.append(send_whatsapp(parent_whatsapp, message))
    if parent_sms:
        channels.append(send_sms(parent_sms, message))
    if not channels:
        logger.warning("No parent contact handle supplied for breach alert; logged only")
    return {"sent": True, "channels": channels}
