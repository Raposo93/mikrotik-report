import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from mikrotik_reporting.aggregation import detection_lookback, week_window
from mikrotik_reporting.models import DetectionBatch, empty_period, initial_state
from mikrotik_reporting.storage import (
    HISTORY_WEEKS,
    SCHEMA_VERSION,
    asn_detection_summary,
    detection_concentration_summary,
    detection_novelty_summary,
    load_history,
    load_state,
    open_database,
    open_database_existing,
    open_database_readonly,
    pending_asn_ips,
    record_asn_lookup,
    record_detection_batch,
    retain_sent_week,
    save_day,
    save_state,
    source_recurrence_summary,
    top_detected_ports,
    top_source_detections,
)


class StorageTests(unittest.TestCase):
    def test_detection_novelty_mixed_known_new_and_partial_lookback(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            closing(open_database(Path(temporary) / "report.sqlite3")) as database,
            database,
        ):
            for day in ("2026-09-20", "2026-09-21"):
                aggregate = empty_period(day)
                aggregate["samples"] = 1
                save_day(database, aggregate)
            for day, source in (
                ("2026-08-23", "192.0.2.20"),
                ("2026-09-20", "192.0.2.10"),
                ("2026-09-21", "192.0.2.10"),
                ("2026-09-21", "192.0.2.20"),
            ):
                database.execute(
                    "INSERT INTO daily_source_detections VALUES (?, ?, 1)",
                    (day, source),
                )
            for day, protocol, port in (
                ("2026-08-23", "udp", 22),
                ("2026-09-20", "tcp", 22),
                ("2026-09-21", "tcp", 22),
                ("2026-09-21", "udp", 22),
            ):
                database.execute(
                    "INSERT INTO daily_detection_events VALUES (?, ?, ?, 1)",
                    (day, protocol, port),
                )
            current = week_window("2026-09-21")
            summary = detection_novelty_summary(
                database, current, detection_lookback(current)
            )
            self.assertEqual(summary["lookback_start"], "2026-08-24")
            self.assertEqual(
                (summary["sampled_days"], summary["expected_days"]), (1, 28)
            )
            for key in ("sources", "ports"):
                self.assertEqual(summary[key]["total"], 2)
                self.assertEqual(summary[key]["new"], 1)
                self.assertEqual(summary[key]["previously_seen"], 1)
            database.execute(
                "INSERT INTO daily_source_detections VALUES (?, ?, 1)",
                ("2026-09-28", "192.0.2.10"),
            )
            database.execute(
                "INSERT INTO daily_detection_events VALUES (?, ?, ?, 1)",
                ("2026-09-28", "tcp", 22),
            )
            known_week = week_window("2026-09-28")
            known = detection_novelty_summary(
                database, known_week, detection_lookback(known_week)
            )
            self.assertEqual(known["sources"]["new"], 0)
            self.assertEqual(known["ports"]["previously_seen"], 1)
            database.execute(
                "INSERT INTO daily_source_detections VALUES (?, ?, 1)",
                ("2026-09-07", "192.0.2.30"),
            )
            database.execute(
                "INSERT INTO daily_detection_events VALUES (?, ?, ?, 1)",
                ("2026-09-07", "tcp", 80),
            )
            new_week = week_window("2026-09-07")
            new = detection_novelty_summary(
                database, new_week, detection_lookback(new_week)
            )
            self.assertEqual(new["sources"]["new"], 1)
            self.assertEqual(new["ports"]["new"], 1)

    def test_detection_novelty_complete_lookback_and_empty_period(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            closing(open_database(Path(temporary) / "report.sqlite3")) as database,
            database,
        ):
            first = date(2026, 8, 24)
            for offset in range(28):
                day = (first + timedelta(days=offset)).isoformat()
                aggregate = empty_period(day)
                aggregate["samples"] = 1
                save_day(database, aggregate)
            current = week_window("2026-09-21")
            summary = detection_novelty_summary(
                database, current, detection_lookback(current)
            )
            self.assertEqual(summary["sampled_days"], 28)
            self.assertEqual(summary["sources"]["total"], 0)
            self.assertEqual(summary["ports"]["total"], 0)

    def test_detection_concentration_even_sources_and_distinct_ports(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            closing(open_database(Path(temporary) / "report.sqlite3")) as database,
            database,
        ):
            for number in range(10):
                database.execute(
                    "INSERT INTO daily_source_detections VALUES (?, ?, ?)",
                    ("2026-09-21", f"192.0.2.{number + 1}", 1),
                )
            database.execute(
                "INSERT INTO daily_detection_events VALUES (?, ?, ?, ?)",
                ("2026-09-21", "tcp", 22, 10),
            )
            start, end = "2026-09-21", "2026-09-28"
            summary = detection_concentration_summary(
                database,
                start,
                end,
                top_source_detections(database, start, end),
                top_detected_ports(database, start, end),
            )
            self.assertEqual(summary["sources"]["top_three_detections"], 3)
            self.assertEqual(summary["sources"]["total_detections"], 10)
            self.assertEqual(summary["ports"]["top_three_detections"], 10)

    def test_detection_concentration_uses_full_totals_and_exact_window(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            closing(open_database(Path(temporary) / "report.sqlite3")) as database,
            database,
        ):
            for number in range(12):
                source = f"192.0.2.{number + 1}"
                count = 20 if number == 0 else 1
                database.execute(
                    "INSERT INTO daily_source_detections VALUES (?, ?, ?)",
                    ("2026-09-21", source, count),
                )
                database.execute(
                    "INSERT INTO daily_detection_events VALUES (?, ?, ?, ?)",
                    ("2026-09-21", "tcp", number + 1, count),
                )
            for day in ("2026-09-20", "2026-09-28"):
                database.execute(
                    "INSERT INTO daily_source_detections VALUES (?, ?, ?)",
                    (day, "203.0.113.30", 100),
                )
                database.execute(
                    "INSERT INTO daily_detection_events VALUES (?, ?, ?, ?)",
                    (day, "udp", 9999, 100),
                )
            sources = top_source_detections(database, "2026-09-21", "2026-09-28")
            ports = top_detected_ports(database, "2026-09-21", "2026-09-28")
            summary = detection_concentration_summary(
                database, "2026-09-21", "2026-09-28", sources, ports
            )
            for item in (summary["sources"], summary["ports"]):
                self.assertEqual(item["total_detections"], 31)
                self.assertEqual(item["top_three_detections"], 22)
                self.assertEqual(item["top_ten_detections"], 29)
            self.assertEqual(
                detection_concentration_summary(
                    database, "2026-10-01", "2026-10-02", [], []
                )["sources"]["total_detections"],
                0,
            )

    def test_state_survives_reopen_and_database_is_private(self) -> None:
        state = initial_state("2026-09-14")
        state["last_sample_at"] = "2026-09-14T00:00:00+00:00"
        state["last_uptime"] = 100
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                save_state(database, state)
            with closing(open_database(path)) as database, database:
                self.assertEqual(load_state(database, "2026-09-14"), state)
                self.assertEqual(
                    database.execute("PRAGMA user_version").fetchone()[0],
                    SCHEMA_VERSION,
                )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_sent_week_history_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                for week in range(15):
                    start = datetime(2026, 1, 5, tzinfo=timezone.utc).date()
                    period = empty_period(
                        (start + timedelta(days=week * 7)).isoformat()
                    )
                    period["samples"] = 2016
                    retain_sent_week(database, period)
            with closing(open_database_existing(path)) as database:
                rows = database.execute(
                    "SELECT start FROM weekly_history ORDER BY start"
                ).fetchall()
                self.assertEqual(len(rows), HISTORY_WEEKS)
                self.assertEqual(rows[0]["start"], "2026-01-26")
                self.assertEqual(len(load_history(database, "2026-04-13")), 3)

    def test_detection_events_are_deduplicated_and_ranked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            baseline: DetectionBatch = {
                "fingerprints": ["old"],
                "events": [
                    {
                        "fingerprint": "old",
                        "day": "2026-09-30",
                        "source_ip": "192.0.2.1",
                        "protocol": "tcp",
                        "destination_port": 22,
                    }
                ],
            }
            new: DetectionBatch = {
                "fingerprints": ["old", "a", "b"],
                "events": [
                    baseline["events"][0],
                    {
                        "fingerprint": "a",
                        "day": "2026-09-30",
                        "source_ip": "192.0.2.2",
                        "protocol": "tcp",
                        "destination_port": 22,
                    },
                    {
                        "fingerprint": "b",
                        "day": "2026-10-01",
                        "source_ip": "192.0.2.3",
                        "protocol": "udp",
                        "destination_port": 6881,
                    },
                ],
            }
            repeated_port: DetectionBatch = {
                "fingerprints": ["a", "b", "c"],
                "events": [
                    new["events"][1],
                    new["events"][2],
                    {
                        "fingerprint": "c",
                        "day": "2026-10-01",
                        "source_ip": "192.0.2.4",
                        "protocol": "tcp",
                        "destination_port": 22,
                    },
                ],
            }
            with closing(open_database(path)) as database, database:
                self.assertEqual(record_detection_batch(database, baseline), 0)
                self.assertEqual(record_detection_batch(database, baseline), 0)
                self.assertEqual(record_detection_batch(database, new), 2)
                self.assertEqual(record_detection_batch(database, repeated_port), 1)
                combined = top_detected_ports(database, "2026-09-30", "2026-10-02")
                october = top_detected_ports(database, "2026-10-01", "2026-11-01")
                cursor_size = database.execute(
                    "SELECT COUNT(*) FROM detection_log_cursor"
                ).fetchone()[0]
                source_rows = database.execute(
                    "SELECT day, source_ip, detections "
                    "FROM daily_source_detections ORDER BY day, source_ip"
                ).fetchall()
            self.assertEqual(
                combined,
                [
                    {"protocol": "tcp", "destination_port": 22, "detections": 2},
                    {
                        "protocol": "udp",
                        "destination_port": 6881,
                        "detections": 1,
                    },
                ],
            )
            self.assertEqual(
                [tuple(row) for row in source_rows],
                [
                    ("2026-09-30", "192.0.2.2", 1),
                    ("2026-10-01", "192.0.2.3", 1),
                    ("2026-10-01", "192.0.2.4", 1),
                ],
            )
            self.assertEqual(
                october,
                [
                    {"protocol": "tcp", "destination_port": 22, "detections": 1},
                    {
                        "protocol": "udp",
                        "destination_port": 6881,
                        "detections": 1,
                    },
                ],
            )
            self.assertEqual(cursor_size, 3)

    def test_repeated_source_events_increment_only_for_new_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            first: DetectionBatch = {
                "fingerprints": ["a", "b"],
                "events": [
                    {
                        "fingerprint": "a",
                        "day": "2026-09-21",
                        "source_ip": "192.0.2.50",
                        "protocol": "tcp",
                        "destination_port": 22,
                    },
                    {
                        "fingerprint": "b",
                        "day": "2026-09-21",
                        "source_ip": "192.0.2.50",
                        "protocol": "tcp",
                        "destination_port": 23,
                    },
                ],
            }
            later: DetectionBatch = {
                "fingerprints": ["a", "b", "c"],
                "events": [
                    *first["events"],
                    {
                        "fingerprint": "c",
                        "day": "2026-09-22",
                        "source_ip": "192.0.2.50",
                        "protocol": "udp",
                        "destination_port": 6881,
                    },
                ],
            }

            with closing(open_database(path)) as database, database:
                self.assertEqual(
                    record_detection_batch(
                        database,
                        {"fingerprints": [], "events": []},
                    ),
                    0,
                )
                self.assertEqual(record_detection_batch(database, first), 2)
                self.assertEqual(record_detection_batch(database, first), 0)
                self.assertEqual(record_detection_batch(database, later), 1)

                daily = database.execute(
                    "SELECT day, source_ip, detections "
                    "FROM daily_source_detections ORDER BY day"
                ).fetchall()
                sources = top_source_detections(
                    database,
                    "2026-09-21",
                    "2026-09-23",
                )

            self.assertEqual(
                [tuple(row) for row in daily],
                [
                    ("2026-09-21", "192.0.2.50", 2),
                    ("2026-09-22", "192.0.2.50", 1),
                ],
            )
            self.assertEqual(
                sources,
                [
                    {
                        "source_ip": "192.0.2.50",
                        "detections": 3,
                        "destination_context": {
                            "detections": 3,
                            "destinations": 3,
                            "dominant_protocol": "tcp",
                            "dominant_destination_port": 22,
                            "dominant_detections": 1,
                        },
                    }
                ],
            )

    def test_router_reboot_resets_detection_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            event: DetectionBatch = {
                "fingerprints": ["reused-after-reboot"],
                "events": [
                    {
                        "fingerprint": "reused-after-reboot",
                        "day": "2026-10-01",
                        "source_ip": "192.0.2.5",
                        "protocol": "tcp",
                        "destination_port": 22,
                    }
                ],
            }
            with closing(open_database(path)) as database, database:
                self.assertEqual(record_detection_batch(database, event), 0)
                self.assertEqual(record_detection_batch(database, event), 0)
                self.assertEqual(
                    record_detection_batch(database, event, reset_cursor=True),
                    1,
                )
                ports = top_detected_ports(database, "2026-10-01", "2026-10-02")
                source = database.execute(
                    "SELECT source_ip, detections FROM daily_source_detections"
                ).fetchone()
            self.assertEqual(
                ports,
                [{"protocol": "tcp", "destination_port": 22, "detections": 1}],
            )
            self.assertEqual(tuple(source), ("192.0.2.5", 1))

    def test_legacy_database_is_migrated_without_losing_state(self) -> None:
        state = initial_state("2026-09-14")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                save_state(database, state)
                database.execute("DROP TABLE weekly_history")
                database.execute("DROP TABLE daily_aggregates")
                database.execute("DROP TABLE monthly_reports")
                database.execute("PRAGMA user_version = 0")
            with closing(open_database_readonly(path)) as database:
                self.assertEqual(load_history(database, "2026-09-21"), {})
            with closing(open_database_existing(path)) as database:
                self.assertEqual(load_state(database, "2026-09-14"), state)
                self.assertEqual(
                    database.execute("PRAGMA user_version").fetchone()[0],
                    SCHEMA_VERSION,
                )
                for table in (
                    "weekly_history",
                    "daily_aggregates",
                    "monthly_reports",
                    "detection_log_state",
                    "detection_log_cursor",
                    "daily_detection_events",
                    "daily_source_detections",
                    "daily_source_port_detections",
                    "ip_asn_metadata",
                ):
                    self.assertIsNotNone(
                        database.execute(
                            "SELECT 1 FROM sqlite_master WHERE name = ?", (table,)
                        ).fetchone()
                    )

    def test_future_schema_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(sqlite3.connect(path)) as database:
                database.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
            with self.assertRaisesRegex(ValueError, "newer than supported"):
                open_database_existing(path)
            with self.assertRaisesRegex(ValueError, "newer than supported"):
                open_database_readonly(path)

    def test_schema_five_history_is_not_given_reconstructed_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(sqlite3.connect(path)) as database:
                database.executescript("""
                    CREATE TABLE daily_source_detections (
                        day TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        detections INTEGER NOT NULL CHECK (detections > 0),
                        PRIMARY KEY (day, source_ip)
                    );
                    INSERT INTO daily_source_detections
                    VALUES ('2026-09-21', '192.0.2.10', 4);
                    PRAGMA user_version = 5;
                """)

            with closing(open_database_readonly(path)) as database:
                self.assertEqual(
                    top_source_detections(database, "2026-09-21", "2026-09-22"),
                    [{"source_ip": "192.0.2.10", "detections": 4}],
                )
            with closing(open_database_existing(path)) as database:
                sources = top_source_detections(database, "2026-09-21", "2026-09-22")
                correlated_rows = database.execute(
                    "SELECT COUNT(*) FROM daily_source_port_detections"
                ).fetchone()[0]
                version = database.execute("PRAGMA user_version").fetchone()[0]

            self.assertEqual(
                sources,
                [{"source_ip": "192.0.2.10", "detections": 4}],
            )
            self.assertEqual(correlated_rows, 0)
            self.assertEqual(version, SCHEMA_VERSION)

    def test_source_detections_are_aggregated_and_ranked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"

            with closing(open_database(path)) as database, database:
                database.executemany(
                    "INSERT INTO daily_source_detections "
                    "(day, source_ip, detections) VALUES (?, ?, ?)",
                    [
                        ("2026-09-20", "192.0.2.10", 3),
                        ("2026-09-21", "192.0.2.10", 4),
                        ("2026-09-21", "192.0.2.20", 7),
                        ("2026-09-21", "192.0.2.30", 2),
                        ("2026-09-22", "192.0.2.40", 100),
                    ],
                )

                sources = top_source_detections(
                    database,
                    "2026-09-20",
                    "2026-09-22",
                )

            self.assertEqual(
                sources,
                [
                    {"source_ip": "192.0.2.10", "detections": 7},
                    {"source_ip": "192.0.2.20", "detections": 7},
                    {"source_ip": "192.0.2.30", "detections": 2},
                ],
            )

    def test_source_recurrence_groups_aggregated_period_totals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                database.executemany(
                    "INSERT INTO daily_source_detections "
                    "(day, source_ip, detections) VALUES (?, ?, ?)",
                    [
                        ("2026-09-20", "192.0.2.1", 50),
                        ("2026-09-21", "192.0.2.10", 1),
                        ("2026-09-21", "192.0.2.20", 1),
                        ("2026-09-22", "192.0.2.20", 1),
                        ("2026-09-21", "192.0.2.30", 5),
                        ("2026-09-21", "192.0.2.40", 6),
                        ("2026-09-21", "192.0.2.50", 100),
                        ("2026-09-28", "192.0.2.60", 1),
                    ],
                )

                summary = source_recurrence_summary(
                    database, "2026-09-21", "2026-09-28"
                )

            self.assertEqual(
                summary,
                {
                    "available": True,
                    "total_source_ips": 5,
                    "one_detection": 1,
                    "two_to_five_detections": 2,
                    "more_than_five_detections": 2,
                },
            )

    def test_source_recurrence_handles_all_one_off_and_empty_periods(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                database.executemany(
                    "INSERT INTO daily_source_detections "
                    "(day, source_ip, detections) VALUES (?, ?, ?)",
                    [
                        ("2026-09-21", "192.0.2.10", 1),
                        ("2026-09-21", "192.0.2.20", 1),
                    ],
                )
                one_offs = source_recurrence_summary(
                    database, "2026-09-21", "2026-09-22"
                )
                empty = source_recurrence_summary(database, "2026-09-22", "2026-09-23")

            self.assertEqual(one_offs["total_source_ips"], 2)
            self.assertEqual(one_offs["one_detection"], 2)
            self.assertEqual(one_offs["two_to_five_detections"], 0)
            self.assertEqual(one_offs["more_than_five_detections"], 0)
            self.assertEqual(
                empty,
                {
                    "available": True,
                    "total_source_ips": 0,
                    "one_detection": 0,
                    "two_to_five_detections": 0,
                    "more_than_five_detections": 0,
                },
            )

    def test_source_recurrence_is_unavailable_without_source_history(self) -> None:
        database = sqlite3.connect(":memory:")
        try:
            self.assertEqual(
                source_recurrence_summary(database, "2026-09-21", "2026-09-22"),
                {
                    "available": False,
                    "total_source_ips": 0,
                    "one_detection": 0,
                    "two_to_five_detections": 0,
                    "more_than_five_detections": 0,
                },
            )
        finally:
            database.close()

    def test_source_destination_context_is_compact_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                database.executemany(
                    "INSERT INTO daily_source_detections "
                    "(day, source_ip, detections) VALUES (?, ?, ?)",
                    [
                        ("2026-09-21", "192.0.2.10", 2),
                        ("2026-09-22", "192.0.2.10", 2),
                        ("2026-09-21", "192.0.2.20", 4),
                        ("2026-09-21", "192.0.2.30", 4),
                        ("2026-09-23", "192.0.2.40", 100),
                    ],
                )
                database.executemany(
                    "INSERT INTO daily_source_port_detections "
                    "(day, source_ip, protocol, destination_port, detections) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [
                        ("2026-09-21", "192.0.2.10", "udp", 6881, 2),
                        ("2026-09-22", "192.0.2.10", "udp", 6881, 2),
                        ("2026-09-21", "192.0.2.20", "tcp", 22, 2),
                        ("2026-09-21", "192.0.2.20", "tcp", 53, 1),
                        ("2026-09-21", "192.0.2.20", "udp", 53, 1),
                        ("2026-09-21", "192.0.2.30", "tcp", 443, 1),
                        ("2026-09-23", "192.0.2.40", "tcp", 23, 100),
                    ],
                )

                sources = top_source_detections(
                    database,
                    "2026-09-21",
                    "2026-09-23",
                )

            self.assertEqual(
                sources,
                [
                    {
                        "source_ip": "192.0.2.10",
                        "detections": 4,
                        "destination_context": {
                            "detections": 4,
                            "destinations": 1,
                            "dominant_protocol": "udp",
                            "dominant_destination_port": 6881,
                            "dominant_detections": 4,
                        },
                    },
                    {
                        "source_ip": "192.0.2.20",
                        "detections": 4,
                        "destination_context": {
                            "detections": 4,
                            "destinations": 3,
                            "dominant_protocol": "tcp",
                            "dominant_destination_port": 22,
                            "dominant_detections": 2,
                        },
                    },
                    {
                        "source_ip": "192.0.2.30",
                        "detections": 4,
                        "destination_context": {
                            "detections": 1,
                            "destinations": 1,
                            "dominant_protocol": "tcp",
                            "dominant_destination_port": 443,
                            "dominant_detections": 1,
                        },
                    },
                ],
            )

    def test_asn_metadata_is_stored_once_and_joined_into_rankings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                database.executemany(
                    "INSERT INTO daily_source_detections "
                    "(day, source_ip, detections) VALUES (?, ?, ?)",
                    [
                        ("2026-09-21", "192.0.2.10", 2),
                        ("2026-09-22", "192.0.2.10", 3),
                    ],
                )
                database.execute(
                    "INSERT INTO ip_asn_metadata (source_ip) VALUES (?)",
                    ("192.0.2.10",),
                )
                self.assertEqual(
                    pending_asn_ips(
                        database,
                        due_at="2026-09-24T10:00:00+00:00",
                        stale_before="2026-08-25T10:00:00+00:00",
                        limit=100,
                    ),
                    ["192.0.2.10"],
                )
                record_asn_lookup(
                    database,
                    ["192.0.2.10"],
                    {
                        "192.0.2.10": {
                            "asn": "64496",
                            "organization": "Example Network",
                        }
                    },
                    "2026-09-24T10:00:00+00:00",
                )
                sources = top_source_detections(database, "2026-09-21", "2026-09-23")
                metadata_count = database.execute(
                    "SELECT COUNT(*) FROM ip_asn_metadata"
                ).fetchone()[0]

            with closing(open_database_readonly(path)) as database:
                self.assertEqual(
                    pending_asn_ips(
                        database,
                        due_at="2026-09-24T10:00:00+00:00",
                        stale_before="2026-08-25T10:00:00+00:00",
                        limit=100,
                    ),
                    [],
                )
            self.assertEqual(metadata_count, 1)
            self.assertEqual(
                sources,
                [
                    {
                        "source_ip": "192.0.2.10",
                        "detections": 5,
                        "asn": "64496",
                        "asn_organization": "Example Network",
                    }
                ],
            )

    def test_asn_retries_back_off_and_success_resets_retry_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                database.execute(
                    "INSERT INTO ip_asn_metadata (source_ip) VALUES (?)",
                    ("192.0.2.10",),
                )
                record_asn_lookup(
                    database,
                    ["192.0.2.10"],
                    {},
                    "2026-09-24T10:00:00+00:00",
                    retry_base_seconds=60,
                    retry_max_seconds=120,
                )
                first = database.execute(
                    "SELECT retry_count, next_retry_at FROM ip_asn_metadata"
                ).fetchone()
                record_asn_lookup(
                    database,
                    ["192.0.2.10"],
                    {},
                    "2026-09-24T10:01:00+00:00",
                    retry_base_seconds=60,
                    retry_max_seconds=120,
                )
                second = database.execute(
                    "SELECT retry_count, next_retry_at FROM ip_asn_metadata"
                ).fetchone()
                record_asn_lookup(
                    database,
                    ["192.0.2.10"],
                    {
                        "192.0.2.10": {
                            "asn": "64496",
                            "organization": "Example Network",
                        }
                    },
                    "2026-09-24T10:03:00+00:00",
                )
                success = database.execute(
                    "SELECT retry_count, next_retry_at, last_error FROM ip_asn_metadata"
                ).fetchone()

            self.assertEqual(tuple(first), (1, "2026-09-24T10:01:00+00:00"))
            self.assertEqual(tuple(second), (2, "2026-09-24T10:03:00+00:00"))
            self.assertEqual(tuple(success), (0, None, None))

    def test_asn_hydration_selects_due_backlog_in_bounded_batches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                database.executemany(
                    "INSERT INTO ip_asn_metadata "
                    "(source_ip, asn, organization, updated_at, next_retry_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [
                        ("192.0.2.1", None, None, None, None),
                        ("192.0.2.2", None, None, None, None),
                        ("192.0.2.3", None, None, None, None),
                        (
                            "192.0.2.4",
                            "64496",
                            "Stale Network",
                            "2026-07-01T00:00:00+00:00",
                            None,
                        ),
                        (
                            "192.0.2.5",
                            "64497",
                            "Fresh Network",
                            "2026-09-20T00:00:00+00:00",
                            None,
                        ),
                        (
                            "192.0.2.6",
                            None,
                            None,
                            None,
                            "2026-09-25T00:00:00+00:00",
                        ),
                    ],
                )
                first = pending_asn_ips(
                    database,
                    due_at="2026-09-24T00:00:00+00:00",
                    stale_before="2026-08-25T00:00:00+00:00",
                    limit=2,
                )
                database.execute(
                    "DELETE FROM ip_asn_metadata WHERE source_ip IN (?, ?)",
                    tuple(first),
                )
                second = pending_asn_ips(
                    database,
                    due_at="2026-09-24T00:00:00+00:00",
                    stale_before="2026-08-25T00:00:00+00:00",
                    limit=2,
                )

            self.assertEqual(first, ["192.0.2.1", "192.0.2.2"])
            self.assertEqual(second, ["192.0.2.3", "192.0.2.4"])

    def test_asn_detection_summary_groups_ips_and_keeps_full_denominator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                database.executemany(
                    "INSERT INTO daily_source_detections "
                    "(day, source_ip, detections) VALUES (?, ?, ?)",
                    [
                        ("2026-09-20", "192.0.2.1", 4),
                        ("2026-09-21", "192.0.2.1", 2),
                        ("2026-09-21", "192.0.2.2", 4),
                        ("2026-09-21", "192.0.2.3", 3),
                        ("2026-09-21", "192.0.2.4", 7),
                        ("2026-09-22", "192.0.2.5", 100),
                    ],
                )
                database.executemany(
                    "INSERT INTO ip_asn_metadata "
                    "(source_ip, asn, organization, updated_at) VALUES (?, ?, ?, ?)",
                    [
                        (
                            "192.0.2.1",
                            "64496",
                            "Example Network",
                            "2026-09-24T00:00:00+00:00",
                        ),
                        (
                            "192.0.2.2",
                            "64496",
                            "Example Network",
                            "2026-09-24T00:00:00+00:00",
                        ),
                        (
                            "192.0.2.3",
                            "64497",
                            "Other Network",
                            "2026-09-24T00:00:00+00:00",
                        ),
                    ],
                )
                summary = asn_detection_summary(
                    database, "2026-09-20", "2026-09-22", limit=1
                )

            self.assertEqual(summary["total_detections"], 20)
            self.assertEqual(summary["resolved_detections"], 13)
            self.assertEqual(summary["total_source_ips"], 4)
            self.assertEqual(summary["resolved_source_ips"], 3)
            self.assertEqual(
                summary["items"],
                [
                    {
                        "asn": "64496",
                        "organization": "Example Network",
                        "detections": 10,
                        "source_ips": 2,
                    }
                ],
            )

    def test_asn_detection_summary_keeps_unresolved_activity_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(open_database(path)) as database, database:
                database.execute(
                    "INSERT INTO daily_source_detections "
                    "(day, source_ip, detections) VALUES (?, ?, ?)",
                    ("2026-09-21", "192.0.2.10", 5),
                )
                summary = asn_detection_summary(database, "2026-09-21", "2026-09-22")

            self.assertEqual(summary["total_detections"], 5)
            self.assertEqual(summary["total_source_ips"], 1)
            self.assertEqual(summary["resolved_detections"], 0)
            self.assertEqual(summary["items"], [])

    def test_schema_four_failure_is_migrated_to_due_retry_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(sqlite3.connect(path)) as database:
                database.executescript("""
                    CREATE TABLE ip_asn_metadata (
                        source_ip TEXT PRIMARY KEY,
                        asn TEXT,
                        organization TEXT,
                        updated_at TEXT,
                        last_attempt_at TEXT,
                        last_error TEXT
                    );
                    INSERT INTO ip_asn_metadata
                    VALUES ('192.0.2.10', NULL, NULL, NULL,
                            '2026-09-24T10:00:00+00:00', 'temporary failure');
                    PRAGMA user_version = 4;
                """)
            with closing(open_database_existing(path)) as database:
                row = database.execute(
                    "SELECT retry_count, next_retry_at FROM ip_asn_metadata"
                ).fetchone()
                version = database.execute("PRAGMA user_version").fetchone()[0]

            self.assertEqual(tuple(row), (1, "2026-09-24T10:00:00+00:00"))
            self.assertEqual(version, SCHEMA_VERSION)

    def test_schema_three_source_history_is_queued_for_asn_hydration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.sqlite3"
            with closing(sqlite3.connect(path)) as database:
                database.executescript("""
                    CREATE TABLE daily_source_detections (
                        day TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        detections INTEGER NOT NULL CHECK (detections > 0),
                        PRIMARY KEY (day, source_ip)
                    );
                    INSERT INTO daily_source_detections
                    VALUES ('2026-09-20', '192.0.2.10', 3);
                    INSERT INTO daily_source_detections
                    VALUES ('2026-09-21', '192.0.2.10', 4);
                    PRAGMA user_version = 3;
                """)
            with closing(open_database_existing(path)) as database:
                pending = pending_asn_ips(
                    database,
                    due_at="2026-09-24T00:00:00+00:00",
                    stale_before="2026-08-25T00:00:00+00:00",
                    limit=100,
                )
                row = database.execute(
                    "SELECT source_ip, retry_count, next_retry_at FROM ip_asn_metadata"
                ).fetchone()
                version = database.execute("PRAGMA user_version").fetchone()[0]

            self.assertEqual(pending, ["192.0.2.10"])
            self.assertEqual(tuple(row), ("192.0.2.10", 0, None))
            self.assertEqual(version, SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
