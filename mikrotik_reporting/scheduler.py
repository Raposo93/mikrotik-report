"""Foreground scheduling for the persistent application mode."""

from __future__ import annotations

import signal
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event
from types import FrameType

from .config import RunConfig

JobAction = Callable[[datetime], None]


@dataclass(frozen=True)
class ScheduledJob:
    name: str
    interval_seconds: int
    action: JobAction


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _next_deadline(deadline: float, interval: int, completed_at: float) -> float:
    elapsed = max(0.0, completed_at - deadline)
    periods = int(elapsed // interval) + 1
    return deadline + periods * interval


def run_scheduler(
    jobs: Sequence[ScheduledJob],
    *,
    stopped: Callable[[], bool],
    wait: Callable[[float], object],
    monotonic: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = _utc_now,
) -> None:
    if not jobs:
        raise ValueError("At least one scheduled job is required")
    if any(job.interval_seconds <= 0 for job in jobs):
        raise ValueError("Scheduled job intervals must be positive")

    started_at = monotonic()
    deadlines = [started_at] * len(jobs)
    while not stopped():
        current = monotonic()
        for index, job in enumerate(jobs):
            if deadlines[index] > current:
                continue
            job.action(now())
            current = monotonic()
            deadlines[index] = _next_deadline(
                deadlines[index], job.interval_seconds, current
            )
            if stopped():
                return
        delay = max(0.0, min(deadlines) - monotonic())
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
    collect_action: JobAction,
    weekly_action: JobAction,
    monthly_action: JobAction,
) -> None:
    jobs = (
        ScheduledJob("collect", config.collect_interval_seconds, collect_action),
        ScheduledJob(
            "weekly-report",
            config.weekly_check_interval_seconds,
            weekly_action,
        ),
        ScheduledJob(
            "monthly-report",
            config.monthly_check_interval_seconds,
            monthly_action,
        ),
    )
    with _termination_event() as stop:
        run_scheduler(jobs, stopped=stop.is_set, wait=stop.wait)
