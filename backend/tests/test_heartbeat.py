"""Tests for dead-man logic: breach suppression + breach triggers."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import db
from app.heartbeat import HeartbeatEvaluator
from app.models import Heartbeat, NetworkState


@pytest.fixture()
def evaluator(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("DATABASE_PATH", db_path)
    db.set_db_path(db_path)
    return HeartbeatEvaluator(db_path=db_path)


def _hb(device_id, battery, boot=1, network=NetworkState.ONLINE, ts=None, **kw):
    return Heartbeat(
        device_id=device_id,
        keystore_signature="dGVzdA==",  # signature verified at route layer, not here
        battery_pct=battery,
        network_state=network,
        boot_count=boot,
        timestamp=ts or datetime.now(timezone.utc),
        **kw,
    )


def test_graceful_low_battery_shutdown_suppressed(evaluator):
    now = datetime.now(timezone.utc)
    evaluator.record(_hb("dev-low", 4, ts=now - timedelta(hours=2)))
    assert evaluator.check_dead_man("dev-low", now=now) is None
    assert evaluator.get_status("dev-low", now=now)["status"] == "GRACEFUL_SHUTDOWN"


def test_brief_gap_under_30_min_suppressed(evaluator):
    now = datetime.now(timezone.utc)
    evaluator.record(_hb("dev-brief", 80, ts=now - timedelta(minutes=10)))
    assert evaluator.check_dead_man("dev-brief", now=now) is None
    assert evaluator.get_status("dev-brief", now=now)["status"] == "HEALTHY"


def test_abrupt_stop_battery_gt_15_network_active_is_critical(evaluator):
    now = datetime.now(timezone.utc)
    evaluator.record(_hb("dev-abrupt", 82, ts=now - timedelta(hours=2)))
    breach = evaluator.check_dead_man("dev-abrupt", now=now)
    assert breach is not None
    assert breach.breach_type.value == "HEARTBEAT_STOPPED"
    assert breach.severity == "CRITICAL"
    assert evaluator.get_status("dev-abrupt", now=now)["status"] == "CRITICAL_TAMPER_BREACH"


def test_long_gap_but_device_was_offline_suppressed(evaluator):
    now = datetime.now(timezone.utc)
    evaluator.record(_hb("dev-off", 80, network=NetworkState.OFFLINE, ts=now - timedelta(hours=3)))
    assert evaluator.check_dead_man("dev-off", now=now) is None


def test_boot_count_reset_is_critical(evaluator):
    evaluator.record(_hb("dev-boot", 80, boot=5))
    result = evaluator.record(_hb("dev-boot", 80, boot=2))
    assert result["breach"] is not None
    assert result["breach"].breach_type.value == "BOOT_COUNT_RESET"


def test_attestation_failure_is_critical(evaluator):
    result = evaluator.record(_hb("dev-att", 80, attestation_valid=False))
    assert result["breach"] is not None
    assert result["breach"].breach_type.value == "ATTESTATION_FAILED"


def test_efrp_wipe_is_critical(evaluator):
    result = evaluator.record(_hb("dev-efrp", 80, efrp_wipe_detected=True))
    assert result["breach"] is not None
    assert result["breach"].breach_type.value == "EFRP_WIPE"


def test_unknown_device_has_no_breach(evaluator):
    assert evaluator.check_dead_man("dev-never-seen") is None
