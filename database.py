"""
database.py - SQLite persistence layer for the Adaptive Network Firewall dashboard.

This is the ONLY place that talks to SQLite. app.py imports these functions.

Stored record (one row per processed packet) follows the shared contract:
    packet fields : src_ip, dst_ip, src_port, dst_port, protocol, flags, size, timestamp
    engine result : action (ALLOW/ALERT/BLOCK), risk (LOW/MEDIUM/HIGH),
                    anomaly_score, reason

Design notes (beginner friendly):
  * The database file is created automatically next to this file
    (firewall_logs.db). Set the FIREWALL_DB_PATH environment variable to change it.
  * init_db() is safe to call as many times as you like (CREATE ... IF NOT EXISTS).
  * Every connection also makes sure the table exists, so a deleted database file
    or a missing table is re-created instead of crashing the dashboard.
  * Read functions never raise: on a database problem they log the error and return
    an empty result. Write functions raise DatabaseError so the UI can tell the user.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional, Sequence

import pandas as pd

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Configuration / constants
# --------------------------------------------------------------------------- #
DB_PATH = Path(
    os.environ.get("FIREWALL_DB_PATH", Path(__file__).resolve().with_name("firewall_logs.db"))
)

VALID_ACTIONS = ("ALLOW", "ALERT", "BLOCK")
VALID_RISKS = ("LOW", "MEDIUM", "HIGH")

TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

# Columns returned (in this order) by get_packets() / get_alerts().
PACKET_FRAME_COLUMNS = [
    "id", "time", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
    "protocol", "flags", "size", "risk", "anomaly_score", "action", "reason",
]
_PACKET_SELECT = (
    "id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, flags, "
    "size, risk, anomaly_score, action, reason"
)

# Fields the engine result must contain before we accept it for storage.
_REQUIRED_KEYS = (
    "src_ip", "dst_ip", "protocol", "timestamp",
    "action", "risk", "anomaly_score", "reason",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     REAL    NOT NULL,
    src_ip        TEXT    NOT NULL,
    src_port      INTEGER,
    dst_ip        TEXT    NOT NULL,
    dst_port      INTEGER,
    protocol      TEXT    NOT NULL,
    flags         TEXT    NOT NULL DEFAULT '',
    size          INTEGER NOT NULL DEFAULT 0,
    risk          TEXT    NOT NULL,
    anomaly_score REAL    NOT NULL DEFAULT 0,
    action        TEXT    NOT NULL,
    reason        TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets (timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_action    ON packets (action);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip    ON packets (src_ip);
"""

_INSERT_SQL = (
    "INSERT INTO packets (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, "
    "flags, size, risk, anomaly_score, action, reason) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


class DatabaseError(Exception):
    """Raised when a write to the database fails."""


# --------------------------------------------------------------------------- #
# Connection helpers
# --------------------------------------------------------------------------- #
def _connect() -> sqlite3.Connection:
    """Open a connection and make sure the schema exists (safe to repeat)."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def init_db() -> bool:
    """Create the database file and tables if needed. Returns True on success."""
    try:
        with closing(_connect()):
            pass
        return True
    except (sqlite3.Error, OSError) as exc:
        logger.error("Database initialisation failed: %s", exc)
        return False


def _query(sql: str, params: Sequence = ()) -> list:
    """Run a read-only query. Returns [] (and logs) if anything goes wrong."""
    try:
        with closing(_connect()) as conn:
            return conn.execute(sql, params).fetchall()
    except (sqlite3.Error, OSError) as exc:
        logger.error("Database query failed: %s", exc)
        return []


# --------------------------------------------------------------------------- #
# Input normalisation (write side)
# --------------------------------------------------------------------------- #
def _to_epoch(value) -> float:
    """Accept epoch numbers, numeric strings, ISO strings or datetime objects."""
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, bool):
        raise ValueError("timestamp cannot be a boolean")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return datetime.fromisoformat(value).timestamp()
    raise ValueError(f"unsupported timestamp: {value!r}")


def _opt_int(value) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _record_to_row(record: dict) -> tuple:
    """Validate one engine result and turn it into a tuple for INSERT."""
    missing = [key for key in _REQUIRED_KEYS if key not in record]
    if missing:
        raise ValueError(f"record is missing fields: {', '.join(missing)}")

    action = str(record["action"]).strip().upper()
    risk = str(record["risk"]).strip().upper()
    if action not in VALID_ACTIONS:
        raise ValueError(f"invalid action: {record['action']!r}")
    if risk not in VALID_RISKS:
        raise ValueError(f"invalid risk: {record['risk']!r}")

    size = _opt_int(record.get("size"))
    return (
        _to_epoch(record["timestamp"]),
        str(record["src_ip"]),
        _opt_int(record.get("src_port")),
        str(record["dst_ip"]),
        _opt_int(record.get("dst_port")),
        str(record["protocol"]).upper(),
        str(record.get("flags") or ""),
        size if size is not None else 0,
        risk,
        float(record["anomaly_score"]),
        action,
        str(record["reason"] or ""),
    )


# --------------------------------------------------------------------------- #
# Writes
# --------------------------------------------------------------------------- #
def insert_packet(record: dict) -> None:
    """Store one processed packet. Raises ValueError (bad record) or DatabaseError."""
    row = _record_to_row(record)
    try:
        with closing(_connect()) as conn:
            with conn:  # commits on success, rolls back on error
                conn.execute(_INSERT_SQL, row)
    except (sqlite3.Error, OSError) as exc:
        raise DatabaseError(f"Could not save packet: {exc}") from exc


def insert_packets(records: Iterable[dict]) -> int:
    """
    Store many processed packets in a single transaction (fast).
    Invalid records are skipped (and logged). Returns the number of rows saved.
    """
    rows = []
    for record in records:
        try:
            rows.append(_record_to_row(record))
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("Skipping invalid record: %s", exc)
    if not rows:
        return 0
    try:
        with closing(_connect()) as conn:
            with conn:
                conn.executemany(_INSERT_SQL, rows)
    except (sqlite3.Error, OSError) as exc:
        raise DatabaseError(f"Could not save packets: {exc}") from exc
    return len(rows)


def clear_packets() -> int:
    """Delete all stored packet records. Returns how many rows were removed."""
    try:
        with closing(_connect()) as conn:
            with conn:
                deleted = conn.execute("DELETE FROM packets").rowcount
                conn.execute("DELETE FROM sqlite_sequence WHERE name = 'packets'")
        return max(deleted, 0)
    except (sqlite3.Error, OSError) as exc:
        raise DatabaseError(f"Could not clear packets: {exc}") from exc


# --------------------------------------------------------------------------- #
# Filters (read side)
# --------------------------------------------------------------------------- #
def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _build_where(actions=None, protocols=None, src_ip=None):
    """
    Build a parameterised WHERE clause.
      None  -> no filter for that field
      []    -> matches nothing
    """
    clauses, params = [], []

    for column, values in (("action", actions), ("protocol", protocols)):
        if values is None:
            continue
        values = [str(v).upper() for v in values]
        if not values:
            clauses.append("1 = 0")
        else:
            clauses.append(f"{column} IN ({', '.join('?' * len(values))})")
            params.extend(values)

    if src_ip and str(src_ip).strip():
        clauses.append("src_ip LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(str(src_ip).strip())}%")

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def _format_time(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime(TIME_FORMAT)[:-3]
    except (TypeError, ValueError, OverflowError, OSError):
        return str(ts)


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #
def get_summary_counts() -> dict:
    """Overall totals: {'total': n, 'ALLOW': n, 'ALERT': n, 'BLOCK': n}."""
    counts = {"total": 0, "ALLOW": 0, "ALERT": 0, "BLOCK": 0}
    for row in _query("SELECT action, COUNT(*) AS n FROM packets GROUP BY action"):
        if row["action"] in counts:
            counts[row["action"]] = row["n"]
    counts["total"] = counts["ALLOW"] + counts["ALERT"] + counts["BLOCK"]
    return counts


def get_packets(limit: int = 500, actions=None, protocols=None, src_ip=None) -> pd.DataFrame:
    """Newest-first traffic log as a DataFrame (empty DataFrame if no rows)."""
    where, params = _build_where(actions, protocols, src_ip)
    sql = f"SELECT {_PACKET_SELECT} FROM packets {where} ORDER BY id DESC LIMIT ?"
    rows = _query(sql, params + [max(int(limit), 1)])
    if not rows:
        return pd.DataFrame(columns=PACKET_FRAME_COLUMNS)

    df = pd.DataFrame([tuple(r) for r in rows], columns=[k for k in rows[0].keys()])
    df.insert(1, "time", df["timestamp"].map(_format_time))
    for col in ("src_port", "dst_port"):
        df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
    return df[PACKET_FRAME_COLUMNS]


def get_alerts(limit: int = 200, protocols=None, src_ip=None) -> pd.DataFrame:
    """Alert history: every ALERT and BLOCK decision, newest first."""
    return get_packets(limit=limit, actions=["ALERT", "BLOCK"], protocols=protocols, src_ip=src_ip)


def get_risk_distribution(actions=None, protocols=None, src_ip=None) -> dict:
    """{'LOW': n, 'MEDIUM': n, 'HIGH': n} - always contains all three keys."""
    where, params = _build_where(actions, protocols, src_ip)
    dist = {risk: 0 for risk in VALID_RISKS}
    for row in _query(f"SELECT risk, COUNT(*) AS n FROM packets {where} GROUP BY risk", params):
        if row["risk"] in dist:
            dist[row["risk"]] = row["n"]
    return dist


def get_traffic_trend(
    bucket_seconds: int = 5,
    max_buckets: int = 60,
    actions=None,
    protocols=None,
    src_ip=None,
) -> pd.DataFrame:
    """
    Packets per time bucket and action, for the most recent `max_buckets` buckets.
    Columns: bucket (epoch seconds), bucket_label (HH:MM:SS), action, packets.
    """
    bucket_seconds = max(int(bucket_seconds), 1)
    max_buckets = max(int(max_buckets), 1)
    columns = ["bucket", "bucket_label", "action", "packets"]

    where, params = _build_where(actions, protocols, src_ip)
    sql = (
        "SELECT CAST(timestamp / ? AS INTEGER) * ? AS bucket, action, COUNT(*) AS packets "
        f"FROM packets {where} GROUP BY bucket, action ORDER BY bucket DESC LIMIT ?"
    )
    rows = _query(sql, [bucket_seconds, bucket_seconds] + params + [max_buckets * len(VALID_ACTIONS)])
    if not rows:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame([tuple(r) for r in rows], columns=["bucket", "action", "packets"])
    keep = sorted(df["bucket"].unique())[-max_buckets:]
    df = df[df["bucket"].isin(keep)].sort_values(["bucket", "action"]).reset_index(drop=True)
    df["bucket_label"] = df["bucket"].map(
        lambda b: datetime.fromtimestamp(int(b)).strftime("%H:%M:%S")
    )
    return df[columns]


def get_protocols() -> list:
    """Distinct protocols seen so far (for the filter drop-down)."""
    return [row["protocol"] for row in _query("SELECT DISTINCT protocol FROM packets ORDER BY protocol")]


def get_blocked_sources(limit: int = 10) -> pd.DataFrame:
    """
    Source IPs that received BLOCK decisions. These are LOGGED decisions only -
    no operating-system firewall rule is created.
    """
    columns = ["src_ip", "block_decisions", "max_anomaly_score", "last_seen"]
    rows = _query(
        "SELECT src_ip, COUNT(*) AS block_decisions, MAX(anomaly_score) AS max_anomaly_score, "
        "MAX(timestamp) AS last_seen FROM packets WHERE action = 'BLOCK' "
        "GROUP BY src_ip ORDER BY block_decisions DESC, last_seen DESC LIMIT ?",
        [max(int(limit), 1)],
    )
    if not rows:
        return pd.DataFrame(columns=columns)
    df = pd.DataFrame([tuple(r) for r in rows], columns=columns)
    df["last_seen"] = df["last_seen"].map(_format_time)
    return df
