"""Domain types and constructors for collected and aggregated RouterOS data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypedDict

SOURCES = ("local", "crowdsec")
METRICS = ("packets", "bytes")
PeriodKind = Literal["day", "week", "month", "range"]


class Snapshot(TypedDict):
    counters: dict[str, dict[str, int]]
    sizes: dict[str, int]
    uptime: int


class DetectionEvent(TypedDict):
    fingerprint: str
    day: str
    source_ip: str
    protocol: str
    destination_port: int


class DetectionBatch(TypedDict):
    fingerprints: list[str]
    events: list[DetectionEvent]


class PortDetection(TypedDict):
    protocol: str
    destination_port: int
    detections: int


class SourceDetectionRequired(TypedDict):
    source_ip: str
    detections: int


class SourceDestinationContext(TypedDict):
    detections: int
    destinations: int
    dominant_protocol: str
    dominant_destination_port: int
    dominant_detections: int


class SourceDetection(SourceDetectionRequired, total=False):
    asn: str
    asn_organization: str
    destination_context: SourceDestinationContext


class ASNMetadata(TypedDict):
    asn: str
    organization: str


class ASNDetection(TypedDict):
    asn: str
    organization: str
    detections: int
    source_ips: int


class ASNSummary(TypedDict):
    items: list[ASNDetection]
    total_detections: int
    resolved_detections: int
    total_source_ips: int
    resolved_source_ips: int


class SourceRecurrenceSummary(TypedDict):
    available: bool
    total_source_ips: int
    one_detection: int
    two_to_five_detections: int
    more_than_five_detections: int


class DetectionConcentration(TypedDict):
    available: bool
    total_detections: int
    top_three_detections: int
    top_ten_detections: int


class DetectionConcentrationSummary(TypedDict):
    sources: DetectionConcentration
    ports: DetectionConcentration


class DetectionNoveltyCounts(TypedDict):
    available: bool
    total: int
    new: int
    previously_seen: int


class DetectionNoveltySummary(TypedDict):
    lookback_start: str
    lookback_end: str
    sampled_days: int
    expected_days: int
    sources: DetectionNoveltyCounts
    ports: DetectionNoveltyCounts


class RankingChanges(TypedDict):
    entered: int
    retained: int
    movement: dict[str, str]


class RankingChurnSummary(TypedDict):
    previous_start: str
    previous_end: str
    unavailable_reason: str | None
    sources: RankingChanges | None
    ports: RankingChanges | None


class Aggregate(TypedDict):
    totals: dict[str, dict[str, int]]
    max_sizes: dict[str, int]
    last_sizes: dict[str, int]
    samples: int
    router_reboots: int
    counter_resets: int
    rule_rebaselines: int


class Period(Aggregate):
    """Persisted aggregate whose start also identifies its calendar window."""

    start: str


class State(TypedDict):
    version: int
    period: Period
    pending: list[Period]
    counters: dict[str, dict[str, int]]
    last_sample_at: str | None
    last_uptime: int | None


@dataclass(frozen=True)
class PeriodWindow:
    """Concrete local-calendar interval used for coverage calculations."""

    start: str
    end: str
    kind: PeriodKind


def empty_period(start: str) -> Period:
    return {
        "start": start,
        "totals": {source: {metric: 0 for metric in METRICS} for source in SOURCES},
        "max_sizes": {source: 0 for source in SOURCES},
        "last_sizes": {source: 0 for source in SOURCES},
        "samples": 0,
        "router_reboots": 0,
        "counter_resets": 0,
        "rule_rebaselines": 0,
    }


def initial_state(start: str) -> State:
    return {
        "version": 1,
        "period": empty_period(start),
        "pending": [],
        "counters": {},
        "last_sample_at": None,
        "last_uptime": None,
    }
