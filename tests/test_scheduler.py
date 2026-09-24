import signal
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import call, patch

from helpers import at, common, mail, router

from mikrotik_reporting.cli import main
from mikrotik_reporting.config import ASNConfig, RunConfig
from mikrotik_reporting.scheduler import (
    ScheduledJob,
    _termination_event,
    run_scheduler,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.waits: list[float] = []
        self.origin = datetime(2026, 9, 24, tzinfo=timezone.utc)

    def monotonic(self) -> float:
        return self.value

    def now(self) -> datetime:
        return self.origin + timedelta(seconds=self.value)

    def wait(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.value += seconds


class SchedulerTests(unittest.TestCase):
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
        schedule = RunConfig(300, 86400, 86400)
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
