"""SQLite schema management and persistence for report state."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import cast

from .aggregation import next_month
from .models import (
    METRICS,
    SOURCES,
    ASNDetection,
    ASNMetadata,
    ASNSummary,
    DetectionBatch,
    Period,
    PortDetection,
    SourceDetection,
    SourceRecurrenceSummary,
    State,
    empty_period,
    initial_state,
)

SCHEMA_VERSION = 6
HISTORY_WEEKS = 12


def _configure(database: sqlite3.Connection) -> sqlite3.Connection:
    database.row_factory = sqlite3.Row
    return database


def _schema_version(database: sqlite3.Connection) -> int:
    return int(database.execute("PRAGMA user_version").fetchone()[0])


def _check_supported_schema(database: sqlite3.Connection) -> int:
    version = _schema_version(database)
    if version > SCHEMA_VERSION:
        raise ValueError(
            f"Database schema version {version} is newer than supported version "
            f"{SCHEMA_VERSION}"
        )
    return version


def _migrate_to_1(database: sqlite3.Connection) -> None:
    # This is also the migration path for databases created before explicit
    # schema versioning; every schema statement is intentionally idempotent.
    database.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_sample_at TEXT,
                last_uptime INTEGER
            );
            CREATE TABLE IF NOT EXISTS counters (
                rule_key TEXT PRIMARY KEY,
                packets INTEGER NOT NULL,
                bytes INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS periods (
                start TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK (status IN ('active', 'pending')),
                local_packets INTEGER NOT NULL,
                local_bytes INTEGER NOT NULL,
                crowdsec_packets INTEGER NOT NULL,
                crowdsec_bytes INTEGER NOT NULL,
                local_max_size INTEGER NOT NULL,
                crowdsec_max_size INTEGER NOT NULL,
                local_last_size INTEGER NOT NULL,
                crowdsec_last_size INTEGER NOT NULL,
                samples INTEGER NOT NULL,
                router_reboots INTEGER NOT NULL,
                counter_resets INTEGER NOT NULL,
                rule_rebaselines INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS weekly_history (
                start TEXT PRIMARY KEY,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS daily_aggregates (
                day TEXT PRIMARY KEY,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS monthly_reports (
                start TEXT PRIMARY KEY,
                sent_at TEXT
            );
            PRAGMA user_version = 1;
            COMMIT;
        """)


def _migrate_to_2(database: sqlite3.Connection) -> None:
    database.executescript("""
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS detection_log_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            initialized INTEGER NOT NULL CHECK (initialized IN (0, 1))
        );
        INSERT OR IGNORE INTO detection_log_state VALUES (1, 0);
        CREATE TABLE IF NOT EXISTS detection_log_cursor (
            fingerprint TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS daily_detection_events (
            day TEXT NOT NULL,
            protocol TEXT NOT NULL,
            destination_port INTEGER NOT NULL
                CHECK (destination_port BETWEEN 0 AND 65535),
            detections INTEGER NOT NULL CHECK (detections > 0),
            PRIMARY KEY (day, protocol, destination_port)
        );
        PRAGMA user_version = 2;
        COMMIT;
    """)


def _migrate_to_3(database: sqlite3.Connection) -> None:
    database.executescript("""
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS daily_source_detections (
            day TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            detections INTEGER NOT NULL CHECK (detections > 0),
            PRIMARY KEY (day, source_ip)
        );
        PRAGMA user_version = 3;
        COMMIT;
    """)


def _migrate_to_4(database: sqlite3.Connection) -> None:
    database.executescript("""
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS ip_asn_metadata (
            source_ip TEXT PRIMARY KEY,
            asn TEXT,
            organization TEXT,
            updated_at TEXT,
            last_attempt_at TEXT,
            last_error TEXT,
            CHECK (
                (asn IS NULL AND organization IS NULL AND updated_at IS NULL)
                OR
                (asn IS NOT NULL AND organization IS NOT NULL AND updated_at IS NOT NULL)
            )
        );
        INSERT OR IGNORE INTO ip_asn_metadata (source_ip)
            SELECT DISTINCT source_ip FROM daily_source_detections;
        PRAGMA user_version = 4;
        COMMIT;
    """)


def _migrate_to_5(database: sqlite3.Connection) -> None:
    database.execute("BEGIN IMMEDIATE")
    try:
        columns = {
            row["name"]
            for row in database.execute("PRAGMA table_info(ip_asn_metadata)")
        }
        if "next_retry_at" not in columns:
            database.execute(
                "ALTER TABLE ip_asn_metadata ADD COLUMN next_retry_at TEXT"
            )
        if "retry_count" not in columns:
            database.execute(
                "ALTER TABLE ip_asn_metadata ADD COLUMN retry_count "
                "INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0)"
            )
        database.execute(
            "UPDATE ip_asn_metadata "
            "SET next_retry_at = last_attempt_at, retry_count = 1 "
            "WHERE updated_at IS NULL AND last_attempt_at IS NOT NULL "
            "AND next_retry_at IS NULL AND retry_count = 0"
        )
        database.execute("PRAGMA user_version = 5")
        database.commit()
    except Exception:
        database.rollback()
        raise


def _migrate_to_6(database: sqlite3.Connection) -> None:
    database.executescript("""
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS daily_source_port_detections (
            day TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            destination_port INTEGER NOT NULL
                CHECK (destination_port BETWEEN 0 AND 65535),
            detections INTEGER NOT NULL CHECK (detections > 0),
            PRIMARY KEY (day, source_ip, protocol, destination_port)
        );
        PRAGMA user_version = 6;
        COMMIT;
    """)


MIGRATIONS = {
    1: _migrate_to_1,
    2: _migrate_to_2,
    3: _migrate_to_3,
    4: _migrate_to_4,
    5: _migrate_to_5,
    6: _migrate_to_6,
}


def ensure_schema(database: sqlite3.Connection) -> None:
    version = _check_supported_schema(database)
    while version < SCHEMA_VERSION:
        target = version + 1
        MIGRATIONS[target](database)
        version = target


def open_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    database = _configure(sqlite3.connect(path, timeout=30))
    os.chmod(path, 0o600)
    try:
        ensure_schema(database)
    except Exception:
        database.close()
        raise
    return database


def open_database_readonly(path: Path) -> sqlite3.Connection:
    database = _configure(
        sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=30)
    )
    try:
        _check_supported_schema(database)
    except Exception:
        database.close()
        raise
    return database


def open_database_existing(path: Path) -> sqlite3.Connection:
    database = _configure(
        sqlite3.connect(f"{path.as_uri()}?mode=rw", uri=True, timeout=30)
    )
    try:
        ensure_schema(database)
    except Exception:
        database.close()
        raise
    return database


def load_day(database: sqlite3.Connection, day: str) -> Period:
    row = database.execute(
        "SELECT data FROM daily_aggregates WHERE day = ?", (day,)
    ).fetchone()
    return cast("Period", json.loads(row["data"])) if row else empty_period(day)


def save_day(database: sqlite3.Connection, day: Period) -> None:
    database.execute(
        "INSERT INTO daily_aggregates (day, data) VALUES (?, ?) "
        "ON CONFLICT(day) DO UPDATE SET data = excluded.data",
        (day["start"], json.dumps(day, sort_keys=True)),
    )


def aggregate_range(
    database: sqlite3.Connection, start: str, end: str
) -> Period | None:
    if not database.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'daily_aggregates'"
    ).fetchone():
        return None
    rows = database.execute(
        "SELECT data FROM daily_aggregates WHERE day >= ? AND day < ? ORDER BY day",
        (start, end),
    ).fetchall()
    if not rows:
        return None
    aggregate = empty_period(start)
    for row in rows:
        day = cast("Period", json.loads(row["data"]))
        for source in SOURCES:
            for metric in METRICS:
                aggregate["totals"][source][metric] += day["totals"][source][metric]
            aggregate["max_sizes"][source] = max(
                aggregate["max_sizes"][source], day["max_sizes"][source]
            )
            aggregate["last_sizes"][source] = day["last_sizes"][source]
        for field in (
            "samples",
            "router_reboots",
            "counter_resets",
            "rule_rebaselines",
        ):
            aggregate[field] += day[field]
    return aggregate


def aggregate_month(database: sqlite3.Connection, start: str) -> Period | None:
    return aggregate_range(database, start, next_month(start))


def record_detection_batch(
    database: sqlite3.Connection,
    batch: DetectionBatch,
    *,
    reset_cursor: bool = False,
) -> int:
    state = database.execute(
        "SELECT initialized FROM detection_log_state WHERE id = 1"
    ).fetchone()
    if state is None:
        raise ValueError("Database is missing detection log state")
    previous = {
        row["fingerprint"]
        for row in database.execute("SELECT fingerprint FROM detection_log_cursor")
    }
    if reset_cursor:
        previous.clear()
    new_fingerprints = set(batch["fingerprints"]) - previous
    recorded = 0
    if state["initialized"]:
        for event in batch["events"]:
            if event["fingerprint"] not in new_fingerprints:
                continue
            database.execute(
                "INSERT INTO daily_detection_events "
                "(day, protocol, destination_port, detections) "
                "VALUES (?, ?, ?, 1) "
                "ON CONFLICT(day, protocol, destination_port) "
                "DO UPDATE SET detections = detections + 1",
                (
                    event["day"],
                    event["protocol"],
                    event["destination_port"],
                ),
            )
            database.execute(
                "INSERT INTO daily_source_detections "
                "(day, source_ip, detections) VALUES (?, ?, 1) "
                "ON CONFLICT(day, source_ip) "
                "DO UPDATE SET detections = detections + 1",
                (event["day"], event["source_ip"]),
            )
            database.execute(
                "INSERT INTO daily_source_port_detections "
                "(day, source_ip, protocol, destination_port, detections) "
                "VALUES (?, ?, ?, ?, 1) "
                "ON CONFLICT(day, source_ip, protocol, destination_port) "
                "DO UPDATE SET detections = detections + 1",
                (
                    event["day"],
                    event["source_ip"],
                    event["protocol"],
                    event["destination_port"],
                ),
            )
            database.execute(
                "INSERT OR IGNORE INTO ip_asn_metadata (source_ip) VALUES (?)",
                (event["source_ip"],),
            )
            recorded += 1
    database.execute("DELETE FROM detection_log_cursor")
    database.executemany(
        "INSERT INTO detection_log_cursor (fingerprint) VALUES (?)",
        ((fingerprint,) for fingerprint in batch["fingerprints"]),
    )
    database.execute("UPDATE detection_log_state SET initialized = 1 WHERE id = 1")
    return recorded


def top_detected_ports(
    database: sqlite3.Connection, start: str, end: str, limit: int = 10
) -> list[PortDetection]:
    if limit <= 0:
        raise ValueError("Detection port limit must be positive")
    if not database.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'daily_detection_events'"
    ).fetchone():
        return []
    rows = database.execute(
        "SELECT protocol, destination_port, SUM(detections) AS detections "
        "FROM daily_detection_events WHERE day >= ? AND day < ? "
        "GROUP BY protocol, destination_port "
        "ORDER BY detections DESC, destination_port, protocol LIMIT ?",
        (start, end, limit),
    ).fetchall()
    return [
        {
            "protocol": row["protocol"],
            "destination_port": row["destination_port"],
            "detections": row["detections"],
        }
        for row in rows
    ]


def top_source_detections(
    database: sqlite3.Connection,
    start: str,
    end: str,
    limit: int = 10,
) -> list[SourceDetection]:
    if limit <= 0:
        raise ValueError("Detection source limit must be positive")
    if not database.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'daily_source_detections'"
    ).fetchone():
        return []
    has_asn_metadata = database.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ip_asn_metadata'"
    ).fetchone()
    if has_asn_metadata:
        rows = database.execute(
            "SELECT detections.source_ip, SUM(detections.detections) AS detections, "
            "metadata.asn, metadata.organization "
            "FROM daily_source_detections AS detections "
            "LEFT JOIN ip_asn_metadata AS metadata "
            "ON metadata.source_ip = detections.source_ip "
            "WHERE detections.day >= ? AND detections.day < ? "
            "GROUP BY detections.source_ip, metadata.asn, metadata.organization "
            "ORDER BY SUM(detections.detections) DESC, detections.source_ip LIMIT ?",
            (start, end, limit),
        ).fetchall()
    else:
        rows = database.execute(
            "SELECT source_ip, SUM(detections) AS detections, "
            "NULL AS asn, NULL AS organization "
            "FROM daily_source_detections WHERE day >= ? AND day < ? "
            "GROUP BY source_ip "
            "ORDER BY detections DESC, source_ip LIMIT ?",
            (start, end, limit),
        ).fetchall()
    results: list[SourceDetection] = []
    for row in rows:
        item: SourceDetection = {
            "source_ip": row["source_ip"],
            "detections": row["detections"],
        }
        if row["asn"] is not None:
            item["asn"] = row["asn"]
            item["asn_organization"] = row["organization"]
        results.append(item)
    has_destination_context = database.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'daily_source_port_detections'"
    ).fetchone()
    if not results or not has_destination_context:
        return results
    source_ips = [item["source_ip"] for item in results]
    placeholders = ", ".join("?" for _ in source_ips)
    context_rows = database.execute(
        "SELECT source_ip, protocol, destination_port, "
        "SUM(detections) AS detections "
        "FROM daily_source_port_detections "
        "WHERE day >= ? AND day < ? "
        f"AND source_ip IN ({placeholders}) "
        "GROUP BY source_ip, protocol, destination_port "
        "ORDER BY source_ip, detections DESC, destination_port, protocol",
        (start, end, *source_ips),
    ).fetchall()
    contexts: dict[str, list[sqlite3.Row]] = {}
    for row in context_rows:
        contexts.setdefault(row["source_ip"], []).append(row)
    for item in results:
        source_context = contexts.get(item["source_ip"])
        if not source_context:
            continue
        dominant = source_context[0]
        item["destination_context"] = {
            "detections": sum(row["detections"] for row in source_context),
            "destinations": len(source_context),
            "dominant_protocol": dominant["protocol"],
            "dominant_destination_port": dominant["destination_port"],
            "dominant_detections": dominant["detections"],
        }
    return results


def source_recurrence_summary(
    database: sqlite3.Connection, start: str, end: str
) -> SourceRecurrenceSummary:
    empty: SourceRecurrenceSummary = {
        "available": False,
        "total_source_ips": 0,
        "one_detection": 0,
        "two_to_five_detections": 0,
        "more_than_five_detections": 0,
    }
    if not database.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'daily_source_detections'"
    ).fetchone():
        return empty
    row = database.execute(
        "WITH source_totals AS ("
        "SELECT source_ip, SUM(detections) AS detections "
        "FROM daily_source_detections WHERE day >= ? AND day < ? "
        "GROUP BY source_ip"
        ") "
        "SELECT COUNT(*) AS total_source_ips, "
        "COALESCE(SUM(CASE WHEN detections = 1 THEN 1 ELSE 0 END), 0) "
        "AS one_detection, "
        "COALESCE(SUM(CASE WHEN detections BETWEEN 2 AND 5 THEN 1 ELSE 0 END), 0) "
        "AS two_to_five_detections, "
        "COALESCE(SUM(CASE WHEN detections > 5 THEN 1 ELSE 0 END), 0) "
        "AS more_than_five_detections "
        "FROM source_totals",
        (start, end),
    ).fetchone()
    return {
        "available": True,
        "total_source_ips": row["total_source_ips"],
        "one_detection": row["one_detection"],
        "two_to_five_detections": row["two_to_five_detections"],
        "more_than_five_detections": row["more_than_five_detections"],
    }


def asn_detection_summary(
    database: sqlite3.Connection,
    start: str,
    end: str,
    limit: int = 10,
) -> ASNSummary:
    if limit <= 0:
        raise ValueError("ASN detection limit must be positive")
    empty: ASNSummary = {
        "items": [],
        "total_detections": 0,
        "resolved_detections": 0,
        "total_source_ips": 0,
        "resolved_source_ips": 0,
    }
    if not database.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = 'daily_source_detections'"
    ).fetchone():
        return empty
    totals = database.execute(
        "SELECT COALESCE(SUM(detections), 0) AS detections, "
        "COUNT(DISTINCT source_ip) AS source_ips "
        "FROM daily_source_detections WHERE day >= ? AND day < ?",
        (start, end),
    ).fetchone()
    summary: ASNSummary = {
        **empty,
        "total_detections": totals["detections"],
        "total_source_ips": totals["source_ips"],
    }
    if not database.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ip_asn_metadata'"
    ).fetchone():
        return summary
    resolved = database.execute(
        "SELECT COALESCE(SUM(detections.detections), 0) AS detections, "
        "COUNT(DISTINCT detections.source_ip) AS source_ips "
        "FROM daily_source_detections AS detections "
        "JOIN ip_asn_metadata AS metadata "
        "ON metadata.source_ip = detections.source_ip "
        "WHERE detections.day >= ? AND detections.day < ? "
        "AND metadata.asn IS NOT NULL",
        (start, end),
    ).fetchone()
    rows = database.execute(
        "SELECT metadata.asn, MIN(metadata.organization) AS organization, "
        "SUM(detections.detections) AS detections, "
        "COUNT(DISTINCT detections.source_ip) AS source_ips "
        "FROM daily_source_detections AS detections "
        "JOIN ip_asn_metadata AS metadata "
        "ON metadata.source_ip = detections.source_ip "
        "WHERE detections.day >= ? AND detections.day < ? "
        "AND metadata.asn IS NOT NULL "
        "GROUP BY metadata.asn "
        "ORDER BY SUM(detections.detections) DESC, "
        "COUNT(DISTINCT detections.source_ip) DESC, metadata.asn LIMIT ?",
        (start, end, limit),
    ).fetchall()
    items: list[ASNDetection] = [
        {
            "asn": row["asn"],
            "organization": row["organization"],
            "detections": row["detections"],
            "source_ips": row["source_ips"],
        }
        for row in rows
    ]
    summary.update(
        items=items,
        resolved_detections=resolved["detections"],
        resolved_source_ips=resolved["source_ips"],
    )
    return summary


def pending_asn_ips(
    database: sqlite3.Connection,
    due_at: str,
    stale_before: str,
    limit: int,
) -> list[str]:
    if limit <= 0:
        raise ValueError("ASN hydration batch limit must be positive")
    rows = database.execute(
        "SELECT source_ip FROM ip_asn_metadata "
        "WHERE (updated_at IS NULL OR updated_at <= ?) "
        "AND (next_retry_at IS NULL OR next_retry_at <= ?) "
        "ORDER BY CASE WHEN updated_at IS NULL THEN 0 ELSE 1 END, "
        "COALESCE(next_retry_at, updated_at, ''), source_ip LIMIT ?",
        (stale_before, due_at, limit),
    ).fetchall()
    return [row["source_ip"] for row in rows]


def record_asn_lookup(
    database: sqlite3.Connection,
    source_ips: list[str],
    results: dict[str, ASNMetadata],
    attempted_at: str,
    *,
    error: str | None = None,
    retry_base_seconds: int = 3600,
    retry_max_seconds: int = 86400,
) -> None:
    attempt_time = datetime.fromisoformat(attempted_at)
    for source_ip in source_ips:
        metadata = results.get(source_ip)
        if metadata is None:
            row = database.execute(
                "SELECT retry_count FROM ip_asn_metadata WHERE source_ip = ?",
                (source_ip,),
            ).fetchone()
            if row is None:
                continue
            retry_count = row["retry_count"] + 1
            exponent = min(retry_count - 1, 30)
            delay = min(retry_base_seconds * (2**exponent), retry_max_seconds)
            next_retry_at = (attempt_time + timedelta(seconds=delay)).isoformat()
            database.execute(
                "UPDATE ip_asn_metadata SET last_attempt_at = ?, next_retry_at = ?, "
                "retry_count = ?, last_error = ? WHERE source_ip = ?",
                (
                    attempted_at,
                    next_retry_at,
                    retry_count,
                    (error or "No ASN mapping returned")[:500],
                    source_ip,
                ),
            )
            continue
        database.execute(
            "UPDATE ip_asn_metadata SET asn = ?, organization = ?, "
            "updated_at = ?, last_attempt_at = ?, next_retry_at = NULL, "
            "retry_count = 0, last_error = NULL WHERE source_ip = ?",
            (
                metadata["asn"],
                metadata["organization"],
                attempted_at,
                attempted_at,
                source_ip,
            ),
        )


def queue_completed_months(database: sqlite3.Connection, current: str) -> None:
    first = database.execute("SELECT MIN(day) AS day FROM daily_aggregates").fetchone()
    if first is None or first["day"] is None:
        return
    month = date.fromisoformat(first["day"]).replace(day=1).isoformat()
    while month < current:
        database.execute(
            "INSERT OR IGNORE INTO monthly_reports (start) VALUES (?)", (month,)
        )
        month = next_month(month)


def next_pending_month(database: sqlite3.Connection, current: str) -> str | None:
    row = database.execute(
        "SELECT start FROM monthly_reports "
        "WHERE sent_at IS NULL AND start < ? ORDER BY start LIMIT 1",
        (current,),
    ).fetchone()
    return cast("str", row["start"]) if row is not None else None


def mark_month_sent(database: sqlite3.Connection, start: str, sent_at: str) -> None:
    database.execute(
        "UPDATE monthly_reports SET sent_at = ? WHERE start = ?", (sent_at, start)
    )


def load_history(database: sqlite3.Connection, start: str) -> dict[str, Period]:
    # Read-only previews may open a legacy database before a writing command migrates it.
    if not database.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'weekly_history'"
    ).fetchone():
        return {}
    rows = database.execute(
        "SELECT start, data FROM weekly_history WHERE start < ? ORDER BY start DESC LIMIT 3",
        (start,),
    ).fetchall()
    return {row["start"]: cast("Period", json.loads(row["data"])) for row in rows}


def retain_sent_week(database: sqlite3.Connection, period: Period) -> None:
    database.execute(
        "INSERT INTO weekly_history (start, data) VALUES (?, ?)",
        (period["start"], json.dumps(period, sort_keys=True)),
    )
    database.execute(
        "DELETE FROM weekly_history WHERE start NOT IN "
        "(SELECT start FROM weekly_history ORDER BY start DESC LIMIT ?)",
        (HISTORY_WEEKS,),
    )


def _period_from_row(row: sqlite3.Row) -> Period:
    period = empty_period(row["start"])
    for source in SOURCES:
        for metric in METRICS:
            period["totals"][source][metric] = row[f"{source}_{metric}"]
        period["max_sizes"][source] = row[f"{source}_max_size"]
        period["last_sizes"][source] = row[f"{source}_last_size"]
    for field in ("samples", "router_reboots", "counter_resets", "rule_rebaselines"):
        period[field] = row[field]
    return period


def load_state(database: sqlite3.Connection, start: str) -> State:
    meta = database.execute("SELECT * FROM metadata WHERE id = 1").fetchone()
    if meta is None:
        return initial_state(start)
    active = database.execute(
        "SELECT * FROM periods WHERE status = 'active'"
    ).fetchall()
    if len(active) != 1:
        raise ValueError("Database must contain exactly one active period")
    pending = database.execute(
        "SELECT * FROM periods WHERE status = 'pending' ORDER BY start"
    ).fetchall()
    counters = database.execute("SELECT * FROM counters").fetchall()
    return {
        "version": 1,
        "period": _period_from_row(active[0]),
        "pending": [_period_from_row(row) for row in pending],
        "counters": {
            row["rule_key"]: {"packets": row["packets"], "bytes": row["bytes"]}
            for row in counters
        },
        "last_sample_at": meta["last_sample_at"],
        "last_uptime": meta["last_uptime"],
    }


def save_state(database: sqlite3.Connection, state: State) -> None:
    database.execute("DELETE FROM metadata")
    database.execute(
        "INSERT INTO metadata VALUES (1, ?, ?)",
        (state["last_sample_at"], state["last_uptime"]),
    )
    database.execute("DELETE FROM counters")
    database.executemany(
        "INSERT INTO counters VALUES (?, ?, ?)",
        (
            (key, value["packets"], value["bytes"])
            for key, value in state["counters"].items()
        ),
    )
    database.execute("DELETE FROM periods")
    for period in state["pending"]:
        _insert_period(database, "pending", period)
    _insert_period(database, "active", state["period"])


def _insert_period(database: sqlite3.Connection, status: str, period: Period) -> None:
    database.execute(
        "INSERT INTO periods VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            period["start"],
            status,
            period["totals"]["local"]["packets"],
            period["totals"]["local"]["bytes"],
            period["totals"]["crowdsec"]["packets"],
            period["totals"]["crowdsec"]["bytes"],
            period["max_sizes"]["local"],
            period["max_sizes"]["crowdsec"],
            period["last_sizes"]["local"],
            period["last_sizes"]["crowdsec"],
            period["samples"],
            period["router_reboots"],
            period["counter_resets"],
            period["rule_rebaselines"],
        ),
    )
