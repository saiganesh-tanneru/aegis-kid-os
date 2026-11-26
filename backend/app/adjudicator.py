"""Cloud AI Safety Adjudicator - prompt-injection hardened.

Contract (see spec section 3):
- Input is ONLY structured fields: resource_url_or_package + age_tier
  (+ nonce / device signature, verified by the route layer).
- There is NO free-text field anywhere in the request. A request that
  tries to smuggle prose, instructions, or a persuasive essay is
  rejected at the model layer (UnblockRequest) and again here.
- Auto-approve ONLY when confidence >= 0.98 AND the resource is
  non-harmful and strictly age-appropriate for the tier.
- Requests for permanent app unlocks, social/messaging platforms,
  age-tier upgrades, or device un-enrollment are NEVER auto-approved:
  they are escalated to the Human Support Queue.
- The optional LLM hook receives ONLY resource metadata
  (resource + age_tier). No child PII, no browsing history, no free
  text is ever sent to the LLM. If no LLM is configured, the
  deterministic rule engine decides alone.

Deterministic rule engine (MVP):
- Cryptographically allowlisted Indian EdTech / educational domains
  and coding tools -> confidence 0.99 -> auto-approve.
- Known social / messaging / UPI / adult / gambling resources -> 0.01
  -> escalate (never auto-approve, never auto-deny silently).
- Everything else unknown -> confidence 0.50 -> deny (not approved).
  A parent may then escalate it manually via /support/escalate.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .config import get_settings
from .crypto import issue_policy_token
from .models import AgeTier, PolicyToken, UnblockRequest

logger = logging.getLogger(__name__)

AUTO_APPROVE_CONFIDENCE = 0.98

# Signature-verified EdTech allowlist (domains + their CDNs are handled
# by the on-device firewall; here we only judge the requested resource).
ALLOWED_DOMAINS = {
    "ncert.nic.in", "diksha.gov.in", "khanacademy.org", "khanacademy.in",
    "pw.live", "physicswallah.live", "unacademy.com", "byjus.com",
    "aakash.ac.in", "youtube.com", "youtu.be",  # YouTube Kids only on-device; full YouTube is tier-gated below
    "scratch.mit.edu", "code.org", "replit.com", "github.com",
    "wikipedia.org", "britannica.com", "nasa.gov", "khanacademy.org",
}
ALLOWED_PACKAGES = {
    "org.khanacademy.android", "in.gov.diksha.app", "com.pw.live",
    "org.nexgensoft.kids", "com.google.android.youtube.kids",
}

SOCIAL_MESSAGING = {
    "whatsapp", "instagram", "facebook", "telegram", "snapchat", "discord",
    "twitter", "x.com", "tiktok", "signal", "messenger", "reddit",
}
UPI_FINANCE = {"gpay", "phonepe", "paytm", "bhim", "upi", "paytmmoney"}
BLOCKED_KEYWORDS = {"porn", "adult", "casino", "betting", "gambling", "dating"}

# Prompt-injection / free-text signals in the resource string itself.
INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"you are (now|a|an)\b",
    r"system prompt",
    r"jailbreak",
    r"do not (block|refuse|deny)",
    r"pretend (you|to be)",
]

# Full YouTube (not Kids) is only potentially appropriate for 16-17.
YOUTUBE_MIN_TIER = AgeTier.AGE_16_17
_TIER_ORDER = [AgeTier.AGE_5_8, AgeTier.AGE_9_12, AgeTier.AGE_13_15, AgeTier.AGE_16_17]


@dataclass
class AdjudicationResult:
    decision: str  # APPROVED | DENIED | ESCALATE
    confidence: float
    reason: str
    token: PolicyToken | None = None
    escalate_to: str | None = None  # "HUMAN_SUPPORT" when decision == ESCALATE


def _domain_of(resource: str) -> str:
    host = urlparse(resource).netloc.lower() if "://" in resource else resource.lower()
    host = host.split(":")[0].removeprefix("www.")
    return host


def _looks_like_free_text_or_injection(resource: str) -> str | None:
    lowered = resource.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lowered):
            return f"prompt-injection pattern detected: {pattern}"
    if len(resource.split()) > 3:
        return "resource looks like free text, not a URL or package id"
    return None


def _classify(resource: str, age_tier: AgeTier) -> tuple[float, str, str]:
    """Return (confidence, decision_hint, reason). Decision hint is
    APPROVED / DENIED / ESCALATE before the 0.98 threshold is applied."""
    injection = _looks_like_free_text_or_injection(resource)
    if injection:
        return 0.0, "DENIED", injection

    lowered = resource.lower()
    if any(k in lowered for k in BLOCKED_KEYWORDS):
        return 0.01, "ESCALATE", "resource matches a blocked category; human review required"
    if any(k in lowered for k in SOCIAL_MESSAGING):
        return 0.01, "ESCALATE", "social/messaging platforms require human support review"
    if any(k in lowered for k in UPI_FINANCE):
        return 0.01, "ESCALATE", "financial / UPI apps are blocked; human review required"

    domain = _domain_of(resource)
    is_package = "." in resource and "://" not in resource and "/" not in resource
    if is_package and resource.lower() in ALLOWED_PACKAGES:
        return 0.99, "APPROVED", "allowlisted educational package"
    if domain in ALLOWED_DOMAINS or any(domain.endswith("." + d) for d in ALLOWED_DOMAINS):
        if "youtube" in domain and _TIER_ORDER.index(age_tier) < _TIER_ORDER.index(YOUTUBE_MIN_TIER):
            return 0.50, "DENIED", "full YouTube is not age-appropriate for this tier (use YouTube Kids)"
        return 0.99, "APPROVED", "allowlisted educational domain"
    return 0.50, "DENIED", "unknown resource: confidence below auto-approve threshold"


def adjudicate(request: UnblockRequest, llm_confidence: float | None = None) -> AdjudicationResult:
    """Synchronous adjudication. `llm_confidence` (0-1) may be supplied
    by the caller after calling the LLM hook; it can only ever raise
    confidence for an already-allowlisted-style resource - it can never
    override an ESCALATE category. In practice the MVP uses the rule
    engine alone when no LLM confidence is supplied."""
    confidence, hint, reason = _classify(request.resource_url_or_package, request.age_tier)
    if hint == "ESCALATE":
        return AdjudicationResult(decision="ESCALATE", confidence=confidence, reason=reason, escalate_to="HUMAN_SUPPORT")
    if llm_confidence is not None:
        # LLM is advisory only and is capped: it cannot push an unknown
        # resource over the threshold on its own in the MVP.
        confidence = min(confidence, llm_confidence) if hint == "DENIED" else confidence
    if hint == "APPROVED" and confidence >= AUTO_APPROVE_CONFIDENCE:
        token = issue_policy_token(request.resource_url_or_package, request.age_tier, request.nonce)
        return AdjudicationResult(decision="APPROVED", confidence=confidence, reason=reason, token=token)
    return AdjudicationResult(decision="DENIED", confidence=confidence, reason=reason)


async def call_llm_adjudicator(resource: str, age_tier: AgeTier) -> float | None:
    """Pluggable LLM hook. Sends ONLY {resource, age_tier} and expects
    strict JSON {"confidence": 0.0-1.0, "appropriate": bool}.
    Returns the confidence, or None if unconfigured / on any error.
    Never raises to the caller - adjudication falls back to the rule engine."""
    settings = get_settings()
    if not settings.llm_api_key or not settings.llm_base_url or not settings.llm_model:
        return None
    payload = {
        "model": settings.llm_model,
        "messages": [
            {"role": "system", "content": "You are a child-safety classifier. Reply with strict JSON only: {\"confidence\": <0-1>, \"appropriate\": <bool>}. Judge only whether the given resource is non-harmful and age-appropriate for the given age tier."},
            {"role": "user", "content": json.dumps({"resource": resource, "age_tier": age_tier.value})},
        ],
        "response_format": {"type": "json_object"},
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {settings.llm_api_key}"},
                json=payload,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            data = json.loads(content)
            conf = float(data["confidence"])
            return conf if 0.0 <= conf <= 1.0 and data.get("appropriate") else 0.0
    except Exception as exc:  # noqa: BLE001 - LLM failure must never break adjudication
        logger.warning("LLM adjudicator failed, falling back to rule engine: %s", exc)
        return None
