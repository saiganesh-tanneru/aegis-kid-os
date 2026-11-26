"""Dead-man heartbeat logic (false-positive aware).

State machine per device, evaluated on every heartbeat and on demand:
  HEALTHY            - heartbeat within the timeout window
  OFFLINE_BRIEF      - gap < timeout (30 min default); no alert
  GRACEFUL_SHUTDOWN  - last battery <= 5% before disconnect; no alert
  CRITICAL_TAMPER_BREACH - one of:
    1. Heartbeats stop abruptly: gap >= timeout AND last battery > 15%
       AND last network_state was online/active.
    2. Hardware Keystore attestation fails on a heartbeat.
    3. boot_count resets (new boot_count < highest seen) on reconnect.
    4. EFRP wipe flag set on a heartbeat (hardware recovery wipe).

Suppression rules (to avoid waking parents for normal events):
- battery <= 5% at last heartbeat -> graceful shutdown, suppress.
- gap < timeout -> brief offline gap (train / Wi-Fi off), suppress.
- last network_state offline/unknown with battery > 15% and a long gap
  is treated as OFFLINE_BRIEF, not a breach: a device that is genuinely
  offline cannot be distinguished from a tampered one, and the spec
  requires network activity for rule 1. The breach fires when the
  device reconnects with a boot_count reset / failed attestation, or
  when the gap is long AND the network was active.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from . import db
from .config import get_settings
from .models import BreachAlert, BreachType, Heartbeat, NetworkState

logger = logging.getLogger(__name__)

GRACEFUL_BATTERY_MAX = 5
ABRUPT_BATTERY_MIN = 15


def _breach(
    device_id: str,
    breach_type: BreachType,
    reason: str,
    last_battery_pct: int | None = None,
    gap_minutes: float | None = None,
) -> BreachAlert:
    return BreachAlert(
        device_id=device_id,
        device_nickname=db.get_device_nickname(device_id),
        breach_type=breach_type,
        detected_at=datetime.now(timezone.utc),
        reason=reason,
        last_battery_pct=last_battery_pct,
        gap_minutes=gap_minutes,
    )


class HeartbeatEvaluator:
    """Records heartbeats and evaluates the dead-man state machine."""

    def __init__(self, db_path: str | None = None) -> None:
        if db_path:
            db.set_db_path(db_path)
        db.init_db()
        self.timeout = timedelta(minutes=get_settings().heartbeat_timeout_minutes)

    # -- ingest -----------------------------------------------------------
    def record(self, hb: Heartbeat) -> dict:
        """Store a heartbeat; return {'stored': True, 'breach': BreachAlert|None}."""
        previous_max_boot = db.get_max_boot_count(hb.device_id)
        db.insert_heartbeat(
            {
                "device_id": hb.device_id,
                "battery_pct": hb.battery_pct,
                "network_state": hb.network_state.value,
                "boot_count": hb.boot_count,
                "timestamp": hb.timestamp.isoformat(),
                "attestation_valid": hb.attestation_valid,
                "efrp_wipe_detected": hb.efrp_wipe_detected,
            }
        )
        breach: BreachAlert | None = None
        if hb.efrp_wipe_detected:
            breach = _breach(
                hb.device_id, BreachType.EFRP_WIPE,
                "Enterprise Factory Reset Protection detected a hardware recovery wipe; device must re-enrol.",
                last_battery_pct=hb.battery_pct,
            )
        elif not hb.attestation_valid:
            breach = _breach(
                hb.device_id, BreachType.ATTESTATION_FAILED,
                "Hardware Keystore attestation failed on heartbeat.",
                last_battery_pct=hb.battery_pct,
            )
        elif previous_max_boot is not None and hb.boot_count < previous_max_boot:
            breach = _breach(
                hb.device_id, BreachType.BOOT_COUNT_RESET,
                f"boot_count reset unexpectedly: {hb.boot_count} < previous max {previous_max_boot}.",
                last_battery_pct=hb.battery_pct,
            )
        if breach:
            db.insert_audit_log("breach_detected", hb.device_id, {"type": breach.breach_type.value})
            logger.warning("Breach for device_id=%s type=%s", hb.device_id, breach.breach_type)
        return {"stored": True, "breach": breach}

    # -- dead-man check ---------------------------------------------------
    def check_dead_man(self, device_id: str, now: datetime | None = None) -> BreachAlert | None:
        """Evaluate the silent-device case. Returns a BreachAlert or None.

        Callers (the watchdog cron / status endpoint) should send the
        alert via app.alerts only when this returns a breach.
        """
        now = now or datetime.now(timezone.utc)
        last = db.get_last_heartbeat(device_id)
        if last is None:
            return None
        last_ts = datetime.fromisoformat(last["timestamp"])
        gap = now - last_ts
        if gap < self.timeout:
            return None  # brief gap: suppressed
        if last["battery_pct"] <= GRACEFUL_BATTERY_MAX:
            return None  # graceful low-battery shutdown: suppressed
        if last["network_state"] != NetworkState.ONLINE.value:
            return None  # device was offline; cannot prove tampering from silence alone
        if last["battery_pct"] <= ABRUPT_BATTERY_MIN:
            return None  # 6-15%: ambiguous low-battery zone; do not alert
        return _breach(
            device_id, BreachType.HEARTBEAT_STOPPED,
            f"Heartbeats stopped abruptly: no heartbeat for {gap.total_seconds() / 60:.0f} min "
            f"while last battery was {last['battery_pct']}% and network was active.",
            last_battery_pct=last["battery_pct"],
            gap_minutes=gap.total_seconds() / 60,
        )

    def get_status(self, device_id: str, now: datetime | None = None) -> dict:
        now = now or datetime.now(timezone.utc)
        last = db.get_last_heartbeat(device_id)
        if last is None:
            return {"device_id": device_id, "status": "UNKNOWN", "last_heartbeat_at": None}
        last_ts = datetime.fromisoformat(last["timestamp"])
        gap_min = (now - last_ts).total_seconds() / 60
        breach = self.check_dead_man(device_id, now=now)
        if breach:
            status = "CRITICAL_TAMPER_BREACH"
        elif last["battery_pct"] <= GRACEFUL_BATTERY_MAX and gap_min >= self.timeout.total_seconds() / 60:
            status = "GRACEFUL_SHUTDOWN"
        elif gap_min >= self.timeout.total_seconds() / 60:
            status = "OFFLINE_BRIEF"
        else:
            status = "HEALTHY"
        return {
            "device_id": device_id,
            "last_heartbeat_at": last_ts,
            "last_battery_pct": last["battery_pct"],
            "last_network_state": last["network_state"],
            "boot_count": last["boot_count"],
            "minutes_since_heartbeat": round(gap_min, 1),
            "status": status,
            "breach": breach,
        }
