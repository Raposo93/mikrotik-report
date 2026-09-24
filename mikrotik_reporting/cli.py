"""Command-line interface for the MikroTik blocking report."""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import urllib.error
from datetime import date, datetime, timezone

from .config import (
    load_asn_config,
    load_common_config,
    load_mail_config,
    load_routeros_config,
    load_run_config,
)
from .scheduler import run_foreground
from .workflows import (
    collect,
    print_range_report,
    send_monthly_reports,
    send_preview,
    send_weekly_reports,
)

DESCRIPTION = "Collect RouterOS counters and produce scheduled or historical reports."


def _date_argument(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"invalid date {value!r}; expected YYYY-MM-DD"
        ) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("collect", "report", "report-monthly", "test-report", "run"):
        commands.add_parser(command)
    range_parser = commands.add_parser(
        "range", help="render a persisted historical date range to stdout"
    )
    range_parser.add_argument(
        "--from",
        dest="start",
        required=True,
        type=_date_argument,
        metavar="YYYY-MM-DD",
        help="inclusive local-calendar start date",
    )
    range_parser.add_argument(
        "--to",
        dest="end",
        required=True,
        type=_date_argument,
        metavar="YYYY-MM-DD",
        help="exclusive local-calendar end date",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    common = load_common_config()
    if args.command == "range":
        print_range_report(common, args.start, args.end)
        return
    if args.command == "run":
        routeros = load_routeros_config()
        asn = load_asn_config()
        weekly_mail = load_mail_config()
        monthly_mail = load_mail_config(monthly=True)
        run_foreground(
            load_run_config(),
            collect_action=lambda current: collect(common, routeros, current, asn),
            weekly_action=lambda current: send_weekly_reports(
                common, weekly_mail, current
            ),
            monthly_action=lambda current: send_monthly_reports(
                common, monthly_mail, current
            ),
        )
        return
    now = datetime.now(timezone.utc)
    if args.command == "collect":
        collect(common, load_routeros_config(), now, load_asn_config())
    elif args.command == "report":
        send_weekly_reports(common, load_mail_config(), now)
    elif args.command == "report-monthly":
        send_monthly_reports(common, load_mail_config(monthly=True), now)
    elif args.command == "test-report":
        send_preview(common, load_routeros_config(), load_mail_config(), now)


def run() -> None:
    try:
        main()
    except (
        ValueError,
        TypeError,
        OSError,
        sqlite3.Error,
        urllib.error.URLError,
        subprocess.CalledProcessError,
        KeyError,
        json.JSONDecodeError,
    ) as error:
        print(f"mikrotik-report: {error}", file=sys.stderr)
        sys.exit(1)
