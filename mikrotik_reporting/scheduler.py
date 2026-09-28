"""Foreground scheduling for the persistent application mode."""

from __future__ import annotations

import signal
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from datetime import time as clock_time
from threading import Event
from types import FrameType
from zoneinfo import ZoneInfo

from .config import RunConfig

JobAction = Callable[[datetime], None]


@dataclass(frozen=True)
class ScheduledJob:
    name: str
    interval_seconds: int
    action: JobAction


@dataclass(frozen=True)
class CalendarJob:
    name: str
    check_time: clock_time
    timezone: ZoneInfo
    action: JobAction


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _next_deadline(deadline: float, interval: int, completed_at: float) -> float:
    elapsed = max(0.0, completed_at - deadline)
    periods = int(elapsed // interval) + 1
    return deadline + periods * interval


def _next_calendar_deadline(
    after: datetime, check_time: clock_time, zone: ZoneInfo
) -> datetime:
    local = after.astimezone(zone)
    day = local.date()
    while True:
        wall = datetime.combine(day, check_time)
        candidate = wall.replace(tzinfo=zone).astimezone(timezone.utc)
        if candidate > after:
            return candidate
        day += timedelta(days=1)


def run_scheduler(
    jobs: Sequence[ScheduledJob | CalendarJob],
    *,
    stopped: Callable[[], bool],
    wait: Callable[[float], object],
    monotonic: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = _utc_now,
) -> None:
    if not jobs:
        raise ValueError("At least one scheduled job is required")
    if any(isinstance(job, ScheduledJob) and job.interval_seconds <= 0 for job in jobs):
        raise ValueError("Scheduled job intervals must be positive")

    started_at = monotonic()
    interval_deadlines = [started_at] * len(jobs)
    calendar_deadlines: list[datetime | None] = [None] * len(jobs)
    while not stopped():
        current = monotonic()
        for index, job in enumerate(jobs):
            if isinstance(job, ScheduledJob):
                if interval_deadlines[index] > current:
                    continue
            else:
                deadline = calendar_deadlines[index]
                if deadline is not None and deadline > now():
                    continue
            job.action(now())
            current = monotonic()
            if isinstance(job, ScheduledJob):
                interval_deadlines[index] = _next_deadline(
                    interval_deadlines[index], job.interval_seconds, current
                )
            else:
                calendar_deadlines[index] = _next_calendar_deadline(
                    now(), job.check_time, job.timezone
                )
            if stopped():
                return
        current = monotonic()
        wall_now = now()
        delays = []
        for index, job in enumerate(jobs):
            if isinstance(job, ScheduledJob):
                delays.append(interval_deadlines[index] - current)
            else:
                deadline = calendar_deadlines[index]
                if deadline is not None:
                    delays.append((deadline - wall_now).total_seconds())
        delay = max(0.0, min(60.0, *delays))
        wait(delay)


@contextmanager
def _termination_event() -> Iterator[Event]:
    stop = Event()

    def request_stop(_signum: int, _frame: FrameType | None) -> None:
        stop.set()

    previous_handlers = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_stop)
    try:
        yield stop
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def run_foreground(
    config: RunConfig,
    *,
    timezone: ZoneInfo,
    collect_action: JobAction,
    weekly_action: JobAction,
    monthly_action: JobAction,
) -> None:
    jobs = (
        ScheduledJob("collect", config.collect_interval_seconds, collect_action),
        CalendarJob(
            "weekly-report",
            config.weekly_check_time,
            timezone,
            weekly_action,
        ),
        CalendarJob(
            "monthly-report",
            config.monthly_check_time,
            timezone,
            monthly_action,
        ),
    )
    with _termination_event() as stop:
        run_scheduler(jobs, stopped=stop.is_set, wait=stop.wait)
