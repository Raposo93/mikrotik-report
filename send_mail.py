#!/usr/bin/env python3
"""Send one plain-text message through a configured SMTP server."""

from __future__ import annotations

import argparse
import os
import smtplib
import ssl
import sys
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path
from typing import TextIO


@dataclass(frozen=True)
class SMTPConfig:
    host: str
    port: int
    tls: str
    user: str
    password: str
    ca_file: str | None
    timeout_seconds: float


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Send a plain-text email whose body is read from standard input."
    )
    parser.add_argument("-t", "--to", required=True, help="recipient address")
    parser.add_argument("-s", "--subject", required=True, help="email subject")
    parser.add_argument("-f", "--from", dest="sender", help="sender header")
    parser.add_argument(
        "-a",
        "--account",
        help="compatibility option; the embedded notifier has one SMTP account",
    )
    return parser


def _nonempty_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} must be set")
    return value


def _smtp_config() -> SMTPConfig:
    host = _nonempty_environment("MIKROTIK_SMTP_HOST")
    tls = os.environ.get("MIKROTIK_SMTP_TLS", "starttls").strip().lower()
    if tls not in ("starttls", "implicit"):
        raise ValueError("MIKROTIK_SMTP_TLS must be starttls or implicit")

    raw_port = os.environ.get(
        "MIKROTIK_SMTP_PORT", "465" if tls == "implicit" else "587"
    ).strip()
    try:
        port = int(raw_port)
    except ValueError as error:
        raise ValueError("MIKROTIK_SMTP_PORT must be an integer") from error
    if not 1 <= port <= 65535:
        raise ValueError("MIKROTIK_SMTP_PORT must be between 1 and 65535")

    raw_timeout = os.environ.get("MIKROTIK_SMTP_TIMEOUT_SECONDS", "15").strip()
    try:
        timeout_seconds = float(raw_timeout)
    except ValueError as error:
        raise ValueError(
            "MIKROTIK_SMTP_TIMEOUT_SECONDS must be a positive number"
        ) from error
    if timeout_seconds <= 0:
        raise ValueError("MIKROTIK_SMTP_TIMEOUT_SECONDS must be a positive number")

    user = os.environ.get("MIKROTIK_SMTP_USER", "").strip()
    password_value = os.environ.get("MIKROTIK_SMTP_PASSWORD")
    password_file = os.environ.get("MIKROTIK_SMTP_PASSWORD_FILE", "").strip()
    if password_value is not None and password_file:
        raise ValueError(
            "set only one of MIKROTIK_SMTP_PASSWORD and MIKROTIK_SMTP_PASSWORD_FILE"
        )
    if password_file:
        password = Path(password_file).read_text(encoding="utf-8").rstrip("\r\n")
    else:
        password = password_value or ""
    if bool(user) != bool(password):
        raise ValueError("MIKROTIK_SMTP_USER and an SMTP password must be set together")

    ca_file = os.environ.get("MIKROTIK_SMTP_CA_FILE", "").strip() or None
    return SMTPConfig(
        host=host,
        port=port,
        tls=tls,
        user=user,
        password=password,
        ca_file=ca_file,
        timeout_seconds=timeout_seconds,
    )


def _mailbox(value: str, label: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError(f"{label} must not contain line breaks")
    _, address = parseaddr(value)
    if not address or "@" not in address:
        raise ValueError(f"{label} must contain an email address")
    return address


def _message(recipient: str, subject: str, sender: str, body: str) -> EmailMessage:
    if not body:
        raise ValueError("message body is empty")
    if "\r" in subject or "\n" in subject:
        raise ValueError("subject must not contain line breaks")
    _mailbox(recipient, "recipient")
    _mailbox(sender, "sender")

    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body, subtype="plain", charset="utf-8")
    return message


def _deliver(config: SMTPConfig, message: EmailMessage) -> None:
    context = ssl.create_default_context(cafile=config.ca_file)
    envelope_from = _mailbox(str(message["From"]), "sender")
    recipient = _mailbox(str(message["To"]), "recipient")

    if config.tls == "implicit":
        client = smtplib.SMTP_SSL(
            config.host,
            config.port,
            timeout=config.timeout_seconds,
            context=context,
        )
    else:
        client = smtplib.SMTP(
            config.host,
            config.port,
            timeout=config.timeout_seconds,
        )

    with client as smtp_client:
        if config.tls == "starttls":
            smtp_client.ehlo()
            smtp_client.starttls(context=context)
            smtp_client.ehlo()
        if config.user:
            smtp_client.login(config.user, config.password)
        smtp_client.send_message(
            message,
            from_addr=envelope_from,
            to_addrs=[recipient],
        )


def main(argv: list[str] | None = None, stdin: TextIO | None = None) -> int:
    args = _parser().parse_args(argv)
    input_stream = stdin if stdin is not None else sys.stdin
    body = input_stream.read()
    try:
        config = _smtp_config()
        sender = args.sender or os.environ.get("MIKROTIK_SMTP_FROM", "").strip()
        sender = sender or config.user
        if not sender:
            raise ValueError(
                "--from, MIKROTIK_SMTP_FROM, or MIKROTIK_SMTP_USER must be set"
            )
        message = _message(args.to, args.subject, sender, body)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    try:
        _deliver(config, message)
    except (OSError, smtplib.SMTPException) as error:
        print(f"Error: mail delivery failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
