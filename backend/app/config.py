"""Environment-based settings. All secrets come from the environment.

No secret is ever hardcoded. Placeholders / empty values mean the
corresponding integration is disabled (or, for DigiLocker/LLM, stubbed
in MVP mock mode) until the operator supplies real credentials via .env.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


@dataclass
class Settings:
    app_name: str = field(default_factory=lambda: _env("APP_NAME", "Aegis-Kid OS Backend"))
    debug: bool = field(default_factory=lambda: _env_bool("DEBUG", False))
    allowed_origins: list[str] = field(
        default_factory=lambda: [
            o.strip() for o in _env("ALLOWED_ORIGINS", "").split(",") if o.strip()
        ]
    )
    database_path: str = field(default_factory=lambda: _env("DATABASE_PATH", "./data/aegis.db"))
    heartbeat_timeout_minutes: int = field(
        default_factory=lambda: _env_int("HEARTBEAT_TIMEOUT_MINUTES", 30)
    )
    # Ed25519 server signing key (base64 seed). Empty = ephemeral dev key.
    ed25519_private_key_b64: str = field(default_factory=lambda: _env("ED25519_PRIVATE_KEY_B64"))
    ed25519_public_key_b64: str = field(default_factory=lambda: _env("ED25519_PUBLIC_KEY_B64"))
    # DigiLocker
    digilocker_base_url: str = field(
        default_factory=lambda: _env("DIGILOCKER_BASE_URL", "https://api.digilocker.gov.in")
    )
    digilocker_client_id: str = field(default_factory=lambda: _env("DIGILOCKER_CLIENT_ID"))
    digilocker_client_secret: str = field(default_factory=lambda: _env("DIGILOCKER_CLIENT_SECRET"))
    digilocker_redirect_uri: str = field(default_factory=lambda: _env("DIGILOCKER_REDIRECT_URI"))
    digilocker_mock_mode: bool = field(default_factory=lambda: _env_bool("DIGILOCKER_MOCK_MODE", True))
    # LLM adjudicator hook (pluggable; only resource metadata is sent)
    llm_api_key: str = field(default_factory=lambda: _env("LLM_API_KEY"))
    llm_base_url: str = field(default_factory=lambda: _env("LLM_BASE_URL"))
    llm_model: str = field(default_factory=lambda: _env("LLM_MODEL"))
    # WhatsApp Business API
    whatsapp_api_url: str = field(
        default_factory=lambda: _env("WHATSAPP_API_URL", "https://graph.facebook.com/v20.0")
    )
    whatsapp_phone_number_id: str = field(default_factory=lambda: _env("WHATSAPP_PHONE_NUMBER_ID"))
    whatsapp_token: str = field(default_factory=lambda: _env("WHATSAPP_TOKEN"))
    whatsapp_template_name: str = field(
        default_factory=lambda: _env("WHATSAPP_TEMPLATE_NAME", "aegis_critical_tamper_breach")
    )
    # SMS fallback
    sms_provider: str = field(default_factory=lambda: _env("SMS_PROVIDER", "msg91"))
    sms_api_key: str = field(default_factory=lambda: _env("SMS_API_KEY"))
    sms_sender_id: str = field(default_factory=lambda: _env("SMS_SENDER_ID", "AEGISKID"))
    twilio_account_sid: str = field(default_factory=lambda: _env("TWILIO_ACCOUNT_SID"))
    twilio_auth_token: str = field(default_factory=lambda: _env("TWILIO_AUTH_TOKEN"))
    twilio_from_number: str = field(default_factory=lambda: _env("TWILIO_FROM_NUMBER"))


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
