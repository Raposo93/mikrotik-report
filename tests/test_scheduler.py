import signal
import sys
import unittest
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from unittest.mock import call, patch
from zoneinfo import ZoneInfo

from helpers import at, common, mail, router

from mikrotik_reporting.cli import main
from mikrotik_reporting.config import ASNConfig, RunConfig
from mikrotik_reporting.scheduler import (
    CalendarJob,
    ScheduledJob,
    _next_calendar_deadline,
    _termination_event,
    run_scheduler,
)


class FakeClock:
    def __init__(self, origin: datetime | None = None) -> None:
        self.value = 0.0
        self.waits: list[float] = []
        self.origin = origin or datetime(2026, 9, 24, tzinfo=timezone.utc)

    def monotonic(self) -> float:
        return self.value

    def now(self) -> datetime:
        return self.origin + timedelta(seconds=self.value)

    def wait(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.value += seconds


class SchedulerTests(unittest.TestCase):
    def test_weekly_and_monthly_checks_use_separate_calendar_times(self) -> None:
        zone = ZoneInfo("Europe/Madrid")
        clock = FakeClock(datetime(2026, 9, 27, 22, 10, tzinfo=timezone.utc))
        events: list[tuple[str, datetime]] = []

        def action(name: str):
            return lambda current: events.append((name, current))

        run_scheduler(
            (
                ScheduledJob("collect", 600, action("collect")),
                CalendarJob("weekly", time(0, 15), zone, action("weekly")),
                CalendarJob("monthly", time(0, 30), zone, action("monthly")),
            ),
            stopped=lambda: sum(name == "monthly" for name, _ in events) == 2,
            wait=clock.wait,
            monotonic=clock.monotonic,
            now=clock.now,
        )
        self.assertEqual(
            events,
            [
                ("collect", clock.origin),
                ("weekly", clock.origin),
                ("monthly", clock.origin),
                ("weekly", datetime(2026, 9, 27, 22, 15, tzinfo=timezone.utc)),
                ("collect", datetime(2026, 9, 27, 22, 20, tzinfo=timezone.utc)),
                ("collect", datetime(2026, 9, 27, 22, 30, tzinfo=timezone.utc)),
                ("monthly", datetime(2026, 9, 27, 22, 30, tzinfo=timezone.utc)),
            ],
        )

    def test_calendar_check_before_and_after_local_time(self) -> None:
        zone = ZoneInfo("Europe/Madrid")
        clock = FakeClock(datetime(2026, 9, 27, 20, 27, tzinfo=timezone.utc))
        events: list[datetime] = []
        job = CalendarJob("weekly", time(0, 15), zone, events.append)
        run_scheduler(
            (job,),
            stopped=lambda: len(events) == 2,
            wait=clock.wait,
            monotonic=clock.monotonic,
            now=clock.now,
        )
        self.assertEqual(
            events,
            [clock.origin, datetime(2026, 9, 27, 22, 15, tzinfo=timezone.utc)],
        )
        self.assertEqual(
            _next_calendar_deadline(events[1], time(0, 15), zone),
            datetime(2026, 9, 28, 22, 15, tzinfo=timezone.utc),
        )

    def test_late_start_recovers_pending_once_and_collect_stays_independent(
        self,
    ) -> None:
        zone = ZoneInfo("Europe/Madrid")
        origin = datetime(2026, 9, 27, 23, 27, tzinfo=timezone.utc)
        delivered: set[str] = set()
        events: list[tuple[str, datetime]] = []

        def weekly(current: datetime) -> None:
            if "2026-09-21" not in delivered:
                delivered.add("2026-09-21")
                events.append(("weekly", current))

        def start_once() -> None:
            clock = FakeClock(origin)
            checks = 0

            def check(current: datetime) -> None:
                nonlocal checks
                checks += 1
                weekly(current)

            run_scheduler(
                (
                    ScheduledJob(
                        "collect",
                        300,
                        lambda current: events.append(("collect", current)),
                    ),
                    CalendarJob("weekly", time(0, 15), zone, check),
                ),
                stopped=lambda: checks == 1,
                wait=clock.wait,
                monotonic=clock.monotonic,
                now=clock.now,
            )

        start_once()
        start_once()
        self.assertEqual(
            events, [("collect", origin), ("weekly", origin), ("collect", origin)]
        )

    def test_calendar_deadline_respects_dst(self) -> None:
        zone = ZoneInfo("Europe/Madrid")
        before_spring = datetime(2026, 3, 28, 23, 45, tzinfo=timezone.utc)
        self.assertEqual(
            _next_calendar_deadline(before_spring, time(0, 15), zone),
            datetime(2026, 3, 29, 22, 15, tzinfo=timezone.utc),
        )
        before_fall = datetime(2026, 10, 24, 22, 45, tzinfo=timezone.utc)
        self.assertEqual(
            _next_calendar_deadline(before_fall, time(0, 15), zone),
            datetime(2026, 10, 25, 23, 15, tzinfo=timezone.utc),
        )
        self.assertEqual(
            _next_calendar_deadline(
                datetime(2026, 3, 29, 0, 30, tzinfo=timezone.utc), time(2, 30), zone
            ),
            datetime(2026, 3, 29, 1, 30, tzinfo=timezone.utc),
        )
        first_fall_check = datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
        self.assertEqual(
            _next_calendar_deadline(
                datetime(2026, 10, 25, 0, 0, tzinfo=timezone.utc), time(2, 30), zone
            ),
            first_fall_check,
        )
        self.assertEqual(
            _next_calendar_deadline(first_fall_check, time(2, 30), zone),
            datetime(2026, 10, 26, 1, 30, tzinfo=timezone.utc),
        )

    def test_jobs_run_immediately_then_at_independent_intervals(self) -> None:
        clock = FakeClock()
        events: list[tuple[str, int]] = []

        def action(name: str):
            return lambda current: events.append(
                (name, int((current - clock.origin).total_seconds()))
            )

        jobs = (
            ScheduledJob("collect", 5, action("collect")),
            ScheduledJob("weekly", 10, action("weekly")),
            ScheduledJob("monthly", 15, action("monthly")),
        )
        run_scheduler(
            jobs,
            stopped=lambda: len(events) >= 10,
            wait=clock.wait,
            monotonic=clock.monotonic,
            now=clock.now,
        )

        self.assertEqual(
            events,
            [
                ("collect", 0),
                ("weekly", 0),
                ("monthly", 0),
                ("collect", 5),
                ("collect", 10),
                ("weekly", 10),
                ("collect", 15),
                ("monthly", 15),
                ("collect", 20),
                ("weekly", 20),
            ],
        )
        self.assertEqual(clock.waits, [5.0, 5.0, 5.0, 5.0])

    def test_slow_job_skips_missed_deadlines_without_overlapping(self) -> None:
        clock = FakeClock()
        starts: list[float] = []

        def slow_action(_current: datetime) -> None:
            starts.append(clock.value)
            clock.value += 12

        run_scheduler(
            (ScheduledJob("slow", 5, slow_action),),
            stopped=lambda: len(starts) >= 2,
            wait=clock.wait,
            monotonic=clock.monotonic,
            now=clock.now,
        )

        self.assertEqual(starts, [0.0, 15.0])
        self.assertEqual(clock.waits, [3.0])

    def test_termination_signals_request_a_clean_stop_and_are_restored(self) -> None:
        with (
            patch(
                "mikrotik_reporting.scheduler.signal.signal",
                return_value=signal.SIG_DFL,
            ) as install,
            _termination_event() as stop,
        ):
            handlers = {
                item.args[0]: item.args[1] for item in install.call_args_list[:2]
            }
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            self.assertTrue(stop.is_set())

        self.assertEqual(
            install.call_args_list[-2:],
            [
                call(signal.SIGINT, signal.SIG_DFL),
                call(signal.SIGTERM, signal.SIG_DFL),
            ],
        )

    def test_cli_run_loads_all_configuration_and_existing_workflows(self) -> None:
        router_path = Path("/tmp/mikrotik-report-test.sqlite3")
        shared = common(router_path)
        routeros = router()
        weekly_mail = mail(router_path.parent)
        monthly_mail = mail(router_path.parent)
        schedule = RunConfig(300, time(0, 15), time(0, 30))
        asn = ASNConfig(False)
        instant = at(24, 12)

        def exercise(_config, **actions) -> None:
            actions["collect_action"](instant)
            actions["weekly_action"](instant)
            actions["monthly_action"](instant)

        with (
            patch.object(sys, "argv", ["mikrotik_report.py", "run"]),
            patch("mikrotik_reporting.cli.load_common_config", return_value=shared),
            patch("mikrotik_reporting.cli.load_routeros_config", return_value=routeros),
            patch(
                "mikrotik_reporting.cli.load_mail_config",
                side_effect=[weekly_mail, monthly_mail],
            ) as load_mail,
            patch("mikrotik_reporting.cli.load_run_config", return_value=schedule),
            patch("mikrotik_reporting.cli.load_asn_config", return_value=asn),
            patch("mikrotik_reporting.cli.collect") as collect,
            patch("mikrotik_reporting.cli.send_weekly_reports") as weekly,
            patch("mikrotik_reporting.cli.send_monthly_reports") as monthly,
            patch(
                "mikrotik_reporting.cli.run_foreground", side_effect=exercise
            ) as foreground,
        ):
            main()

        foreground.assert_called_once()
        collect.assert_called_once_with(shared, routeros, instant, asn)
        weekly.assert_called_once_with(shared, weekly_mail, instant)
        monthly.assert_called_once_with(shared, monthly_mail, instant)
        self.assertEqual(load_mail.call_args_list, [call(), call(monthly=True)])


if __name__ == "__main__":
    unittest.main()
