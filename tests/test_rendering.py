import unittest

from helpers import UTC

from mikrotik_reporting.models import SourceRecurrenceSummary, empty_period
from mikrotik_reporting.rendering import render_monthly_report, render_weekly_report


class RenderingTests(unittest.TestCase):
    def test_detected_destination_ports_are_compact_and_labeled(self) -> None:
        period = empty_period("2026-09-21")
        rendered = render_weekly_report(
            period,
            UTC,
            completed=False,
            top_ports=[
                {"protocol": "udp", "destination_port": 6881, "detections": 312},
                {"protocol": "tcp", "destination_port": 22, "detections": 1},
            ],
        )
        self.assertIn("Top detected destination ports", rendered)
        self.assertIn("6881/udp", rendered)
        self.assertIn("312 detections", rendered)
        self.assertIn("22/tcp", rendered)
        self.assertIn("1 detection\n", rendered)
        self.assertIn("detection events, not unique attacks or packets", rendered)

    def test_empty_destination_port_data_is_explicit(self) -> None:
        rendered = render_monthly_report(empty_period("2026-09-01"), None, UTC, [])
        self.assertIn("No detection events recorded", rendered)

    def test_weekly_comparison_zero_baseline_and_missing_history(self) -> None:
        previous = empty_period("2026-09-14")
        current = empty_period("2026-09-21")
        previous["samples"] = current["samples"] = 2016
        current["totals"]["local"]["packets"] = 50
        current["totals"]["local"]["bytes"] = 5000
        current["totals"]["crowdsec"]["packets"] = 20
        previous["totals"]["crowdsec"]["packets"] = 10
        current["last_sizes"]["local"] = 4
        previous["last_sizes"]["local"] = 2
        rendered = render_weekly_report(current, UTC, {previous["start"]: previous})
        self.assertIn("Local packets: 50 vs 0; +50 (n/a (zero baseline), up)", rendered)
        self.assertIn("CrowdSec packets: 20 vs 10; +10 (+100.0%, up)", rendered)
        self.assertIn("Local latest list size: 4 vs 2; +2 (+100.0%, up)", rendered)
        self.assertIn("Samples: 2,016 / ~2,016 expected", rendered)
        self.assertIn("Coverage: ~100.0%", rendered)
        self.assertIn("2026-09-07: unavailable (no retained history)", rendered)
        self.assertIn("2026-09-14: local 0 packets", rendered)
        self.assertIn(
            "previous calendar week has no retained history",
            render_weekly_report(current, UTC),
        )

    def test_low_coverage_history_is_not_compared_as_zero(self) -> None:
        previous = empty_period("2026-09-14")
        current = empty_period("2026-09-21")
        previous["samples"] = 40
        current["samples"] = 2016
        rendered = render_weekly_report(current, UTC, {previous["start"]: previous})
        self.assertIn("previous calendar week has low sample coverage", rendered)
        self.assertIn(
            "2026-09-14: unavailable (low coverage: 40 / ~2,016, ~2.0%)",
            rendered,
        )
        self.assertNotIn("Local packets: 0 vs 0", rendered)

    def test_monthly_comparison_and_missing_history(self) -> None:
        previous = empty_period("2026-08-01")
        current = empty_period("2026-09-01")
        previous["samples"] = 8928
        current["samples"] = 8640
        previous["totals"]["local"]["packets"] = 10
        current["totals"]["local"]["packets"] = 30
        current["totals"]["crowdsec"]["bytes"] = 100
        rendered = render_monthly_report(current, previous, UTC)
        self.assertIn("2026-09-01 to 2026-10-01 (UTC, end exclusive)", rendered)
        self.assertIn("Month over month", rendered)
        self.assertIn("Local packets: 30 vs 10; +20 (+200.0%, up)", rendered)
        self.assertIn(
            "CrowdSec bytes: 100 vs 0; +100 (n/a (zero baseline), up)", rendered
        )
        self.assertIn("Samples: 8,640 / ~8,640 expected", rendered)
        self.assertIn(
            "previous calendar month has no retained history",
            render_monthly_report(current, None, UTC),
        )
        previous["samples"] = 20
        self.assertIn(
            "previous calendar month has low sample coverage",
            render_monthly_report(current, previous, UTC),
        )

    def test_empty_month_marks_activity_unavailable(self) -> None:
        rendered = render_monthly_report(empty_period("2026-10-01"), None, UTC)
        self.assertIn("Packets dropped: unavailable", rendered)
        self.assertIn("zero totals do not mean zero blocked traffic", rendered)

    def test_recurring_source_ips_are_compact_and_labeled(self) -> None:
        period = empty_period("2026-09-21")

        rendered = render_weekly_report(
            period,
            UTC,
            top_sources=[
                {
                    "source_ip": "192.0.2.10",
                    "detections": 17,
                    "asn": "64496",
                    "asn_organization": "Example Network",
                    "destination_context": {
                        "detections": 17,
                        "destinations": 1,
                        "dominant_protocol": "udp",
                        "dominant_destination_port": 6881,
                        "dominant_detections": 17,
                    },
                },
                {
                    "source_ip": "192.0.2.20",
                    "detections": 5,
                    "destination_context": {
                        "detections": 2,
                        "destinations": 2,
                        "dominant_protocol": "tcp",
                        "dominant_destination_port": 22,
                        "dominant_detections": 1,
                    },
                },
                {"source_ip": "192.0.2.30", "detections": 1},
            ],
        )

        self.assertIn("Top recurring source IPs", rendered)
        self.assertIn("192.0.2.10", rendered)
        self.assertIn("AS64496 Example Network", rendered)
        self.assertIn("17 detections", rendered)
        self.assertIn("1 port/protocol pair; dominant 6881/udp", rendered)
        self.assertIn("17 detections (100.0% of contextualized detections)", rendered)
        self.assertIn("192.0.2.20", rendered)
        self.assertIn("2 / 5 detections available", rendered)
        self.assertIn("2 port/protocol pairs; dominant 22/tcp", rendered)
        self.assertIn("192.0.2.30", rendered)
        self.assertIn(
            "Destination context: unavailable for historical detections.", rendered
        )
        self.assertIn("1 detection", rendered)

    def test_empty_source_ip_data_is_explicit(self) -> None:
        period = empty_period("2026-09-21")

        rendered = render_weekly_report(
            period,
            UTC,
            top_sources=[],
        )

        self.assertIn("Top recurring source IPs", rendered)
        self.assertIn("No detection events recorded.", rendered)

    def test_source_recurrence_is_compact_and_deterministic(self) -> None:
        period = empty_period("2026-09-21")
        period["samples"] = 1
        summary: SourceRecurrenceSummary = {
            "available": True,
            "total_source_ips": 10,
            "one_detection": 6,
            "two_to_five_detections": 3,
            "more_than_five_detections": 1,
        }

        rendered = render_weekly_report(
            period, UTC, completed=False, source_recurrence=summary
        )

        expected = (
            "Source detection recurrence\n"
            "  Unique source IPs: 10\n"
            "  Exactly 1 detection: 6\n"
            "  2–5 detections: 3\n"
            "  More than 5 detections: 1\n"
            "  Counts group observed source IPs by detection events, not packets or "
            "confirmed attacks."
        )
        self.assertIn(expected, rendered)

    def test_source_recurrence_empty_and_unavailable_are_explicit(self) -> None:
        observed = empty_period("2026-09-01")
        observed["samples"] = 1
        empty_summary: SourceRecurrenceSummary = {
            "available": True,
            "total_source_ips": 0,
            "one_detection": 0,
            "two_to_five_detections": 0,
            "more_than_five_detections": 0,
        }
        unavailable_summary: SourceRecurrenceSummary = {
            **empty_summary,
            "available": False,
        }

        empty = render_monthly_report(
            observed, None, UTC, source_recurrence=empty_summary
        )
        unavailable_history = render_monthly_report(
            observed, None, UTC, source_recurrence=unavailable_summary
        )
        no_samples = render_monthly_report(
            empty_period("2026-09-01"),
            None,
            UTC,
            source_recurrence=empty_summary,
        )

        self.assertIn("Source detection recurrence", empty)
        self.assertIn("No source detection events recorded.", empty)
        self.assertIn("source-detection history is not available", unavailable_history)
        self.assertIn("no collector samples were recorded", no_samples)

    def test_asn_summary_shows_grouped_activity_share_and_coverage(self) -> None:
        rendered = render_weekly_report(
            empty_period("2026-09-21"),
            UTC,
            completed=False,
            asn_summary={
                "items": [
                    {
                        "asn": "64496",
                        "organization": "Example Network",
                        "detections": 10,
                        "source_ips": 2,
                    },
                    {
                        "asn": "64497",
                        "organization": "Other Network",
                        "detections": 3,
                        "source_ips": 1,
                    },
                ],
                "total_detections": 20,
                "resolved_detections": 13,
                "total_source_ips": 4,
                "resolved_source_ips": 3,
            },
        )

        self.assertIn("Top source ASNs", rendered)
        self.assertIn("AS64496 Example Network", rendered)
        self.assertIn("10 detections; 2 source IPs; 50.0%", rendered)
        self.assertIn("13 / 20 detections (65.0%)", rendered)
        self.assertIn("3 / 4 source IPs (75.0%)", rendered)
        self.assertIn("not firewall packet or byte counters", rendered)

    def test_asn_summary_is_sensible_when_metadata_is_unavailable(self) -> None:
        rendered = render_weekly_report(
            empty_period("2026-09-21"),
            UTC,
            completed=False,
            top_sources=[{"source_ip": "192.0.2.10", "detections": 5}],
            asn_summary={
                "items": [],
                "total_detections": 5,
                "resolved_detections": 0,
                "total_source_ips": 1,
                "resolved_source_ips": 0,
            },
        )

        self.assertIn("192.0.2.10", rendered)
        self.assertIn("No ASN metadata available", rendered)


if __name__ == "__main__":
    unittest.main()
