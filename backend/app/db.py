"""SQLite persistence for the MVP (stdlib sqlite3, no ORM).

RETENTION & DPDP POLICY - READ BEFORE EDITING:
- heartbeats: retained 30 days, then purged by purge_old_heartbeats().
- tokens / nonces: retained only until expiry, then purged.
- escalations / audit_log: structured metadata only, no child content.
- THERE IS NO TABLE for browsing history, app usage, screenshots,
  search queries, or voice/text. Do NOT create one. Any such data
  arriving at the API layer must be rejected, not stored.

All timestamps are stored as ISO-8601 UTC strings.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import get_settings

_lock = threading.Lock()
_db_path: str | None = None


def set_db_path(path: str) -> None:
    global _db_path
    _db_path = path


def get_db_path() -> str:
    if _db_path:
        return _db_path
    return get_settings().database_path


def _connect(path: str | None = None) -> sqlite3.Connection:
    p = Path(path or get_db_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path: str | None = None) -> str:
    """Create all tables if missing. Idempotent. Returns the DB path."""
    if path:
        set_db_path(path)
    db_path = get_db_path()
    with _lock, _connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                public_key_b64 TEXT NOT NULL,
                device_nickname TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS heartbeats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                battery_pct INTEGER NOT NULL,
                network_state TEXT NOT NULL,
                boot_count INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                attestation_valid INTEGER NOT NULL DEFAULT 1,
                efrp_wipe_detected INTEGER NOT NULL DEFAULT 0,
                received_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_heartbeats_device_time
                ON heartbeats(device_id, timestamp);
            CREATE TABLE IF NOT EXISTS tokens (
                nonce TEXT PRIMARY KEY,
                resource TEXT NOT NULL,
                age_tier TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                signature TEXT NOT NULL,
                issued_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nonces (
                nonce TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS escalations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                resource TEXT NOT NULL,
                age_tier TEXT NOT NULL,
                request_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                digilocker_verified INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                device_id TEXT,
                detail TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            """
        )
    return db_path


# --- devices -------------------------------------------------------------
def register_device(device_id: str, public_key_b64: str, nickname: str | None = None) -> None:
    init_db()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO devices(device_id, public_key_b64, device_nickname, created_at)"
            " VALUES (?, ?, ?, ?)",
            (device_id, public_key_b64, nickname, datetime.now(timezone.utc).isoformat()),
        )


def get_device_public_key(device_id: str) -> str | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT public_key_b64 FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
    return row["public_key_b64"] if row else None


def get_device_nickname(device_id: str) -> str | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT device_nickname FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
    return row["device_nickname"] if row and row["device_nickname"] else None


# --- heartbeats ----------------------------------------------------------
def insert_heartbeat(row: dict[str, Any]) -> None:
    init_db()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO heartbeats(device_id, battery_pct, network_state, boot_count,"
            " timestamp, attestation_valid, efrp_wipe_detected, received_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row["device_id"],
                row["battery_pct"],
                row["network_state"],
                row["boot_count"],
                row["timestamp"],
                1 if row.get("attestation_valid", True) else 0,
                1 if row.get("efrp_wipe_detected", False) else 0,
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def get_last_heartbeat(device_id: str) -> dict[str, Any] | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM heartbeats WHERE device_id = ? ORDER BY timestamp DESC LIMIT 1",
            (device_id,),
        ).fetchone()
    return dict(row) if row else None


def get_max_boot_count(device_id: str) -> int | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT MAX(boot_count) AS m FROM heartbeats WHERE device_id = ?", (device_id,)
        ).fetchone()
    return row["m"] if row and row["m"] is not None else None


def purge_old_heartbeats(days: int = 30) -> int:
    """Delete heartbeats older than `days`. Returns rows deleted."""
    init_db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with _lock, _connect() as conn:
        cur = conn.execute("DELETE FROM heartbeats WHERE timestamp < ?", (cutoff,))
        return cur.rowcount


# --- tokens / nonces -----------------------------------------------------
def insert_token(token: dict[str, Any]) -> None:
    init_db()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO tokens(nonce, resource, age_tier, expires_at, signature, issued_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                token["nonce"],
                token["resource"],
                token["age_tier"],
                token["expires_at"],
                token["signature"],
                token["issued_at"],
            ),
        )


def is_nonce_seen(nonce: str, device_id: str = "") -> bool:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,)).fetchone()
    return row is not None


def store_nonce(nonce: str, device_id: str, expires_at: datetime) -> None:
    init_db()
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO nonces(nonce, device_id, expires_at) VALUES (?, ?, ?)",
            (nonce, device_id, expires_at.isoformat()),
        )


# --- escalations ---------------------------------------------------------
def insert_escalation(row: dict[str, Any]) -> int:
    init_db()
    with _lock, _connect() as conn:
        cur = conn.execute(
            "INSERT INTO escalations(device_id, resource, age_tier, request_type, status,"
            " digilocker_verified, created_at) VALUES (?, ?, ?, ?, 'PENDING', ?, ?)",
            (
                row["device_id"],
                row["resource"],
                row["age_tier"],
                row["request_type"],
                1 if row.get("digilocker_verified") else 0,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return cur.lastrowid


def get_escalation(esc_id: int) -> dict[str, Any] | None:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM escalations WHERE id = ?", (esc_id,)).fetchone()
    return dict(row) if row else None


def list_escalations(status: str | None = None) -> list[dict[str, Any]]:
    init_db()
    with _connect() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM escalations WHERE status = ? ORDER BY created_at DESC", (status,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM escalations ORDER BY created_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


def update_escalation_status(esc_id: int, status: str, decided_by: str) -> bool:
    init_db()
    with _lock, _connect() as conn:
        cur = conn.execute(
            "UPDATE escalations SET status = ?, decided_at = ?, decided_by = ?"
            " WHERE id = ? AND status = 'PENDING'",
            (status, datetime.now(timezone.utc).isoformat(), decided_by, esc_id),
        )
        return cur.rowcount == 1


# --- audit log (structured metadata only, never child content) -----------
def insert_audit_log(event: str, device_id: str | None, detail: dict[str, Any]) -> None:
    init_db()
    # Defensive: strip any forbidden keys if a caller ever passes them.
    forbidden = {"browsing_history", "app_usage", "screenshot", "search_query", "voice", "text_input"}
    safe = {k: v for k, v in detail.items() if k not in forbidden}
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO audit_log(event, device_id, detail, created_at) VALUES (?, ?, ?, ?)",
            (event, device_id, json.dumps(safe), datetime.now(timezone.utc).isoformat()),
        )
