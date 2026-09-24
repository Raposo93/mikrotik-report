import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import send_mail


class SendMailTests(unittest.TestCase):
    def test_sends_plain_text_with_starttls_and_authentication(self) -> None:
        environment = {
            "MIKROTIK_SMTP_HOST": "smtp.example.net",
            "MIKROTIK_SMTP_USER": "mailer@example.net",
            "MIKROTIK_SMTP_PASSWORD": "private-password",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch("send_mail.smtplib.SMTP") as smtp,
        ):
            result = send_mail.main(
                [
                    "--account",
                    "notifications",
                    "--from",
                    "Router report <reports@example.net>",
                    "--to",
                    "recipient@example.net",
                    "--subject",
                    "Weekly report",
                ],
                StringIO("Report body\n"),
            )

        self.assertEqual(result, 0)
        smtp.assert_called_once_with("smtp.example.net", 587, timeout=15.0)
        client = smtp.return_value.__enter__.return_value
        client.starttls.assert_called_once()
        client.login.assert_called_once_with("mailer@example.net", "private-password")
        message = client.send_message.call_args.args[0]
        self.assertEqual(message["From"], "Router report <reports@example.net>")
        self.assertEqual(message["To"], "recipient@example.net")
        self.assertEqual(message["Subject"], "Weekly report")
        self.assertEqual(message.get_content(), "Report body\n")
        self.assertEqual(
            client.send_message.call_args.kwargs["from_addr"], "reports@example.net"
        )

    def test_supports_implicit_tls_and_password_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            password_file = Path(temporary) / "smtp-password"
            password_file.write_text("private-password\n", encoding="utf-8")
            environment = {
                "MIKROTIK_SMTP_HOST": "smtp.example.net",
                "MIKROTIK_SMTP_TLS": "implicit",
                "MIKROTIK_SMTP_USER": "mailer@example.net",
                "MIKROTIK_SMTP_PASSWORD_FILE": str(password_file),
            }
            with (
                patch.dict(os.environ, environment, clear=True),
                patch("send_mail.smtplib.SMTP_SSL") as smtp_ssl,
            ):
                result = send_mail.main(
                    [
                        "--to",
                        "recipient@example.net",
                        "--subject",
                        "Monthly report",
                    ],
                    StringIO("Report body"),
                )

        self.assertEqual(result, 0)
        smtp_ssl.return_value.__enter__.return_value.login.assert_called_once_with(
            "mailer@example.net", "private-password"
        )
        call = smtp_ssl.call_args
        self.assertEqual(call.args, ("smtp.example.net", 465))
        self.assertEqual(call.kwargs["timeout"], 15.0)
        self.assertIn("context", call.kwargs)
        smtp_ssl.return_value.__enter__.return_value.starttls.assert_not_called()

    def test_rejects_empty_body_before_connecting(self) -> None:
        environment = {
            "MIKROTIK_SMTP_HOST": "smtp.example.net",
            "MIKROTIK_SMTP_FROM": "mailer@example.net",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch("send_mail.smtplib.SMTP") as smtp,
            patch("sys.stderr", new_callable=StringIO) as stderr,
        ):
            result = send_mail.main(
                ["--to", "recipient@example.net", "--subject", "Report"],
                StringIO(""),
            )

        self.assertEqual(result, 2)
        self.assertIn("message body is empty", stderr.getvalue())
        smtp.assert_not_called()

    def test_requires_user_and_password_together(self) -> None:
        environment = {
            "MIKROTIK_SMTP_HOST": "smtp.example.net",
            "MIKROTIK_SMTP_USER": "mailer@example.net",
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch("sys.stderr", new_callable=StringIO) as stderr,
        ):
            result = send_mail.main(
                ["--to", "recipient@example.net", "--subject", "Report"],
                StringIO("Report body"),
            )

        self.assertEqual(result, 2)
        self.assertIn("must be set together", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
