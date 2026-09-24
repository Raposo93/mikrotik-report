import os
import unittest
from pathlib import Path
from unittest.mock import patch

from mikrotik_reporting.config import load_mail_config, load_run_config


class ConfigTests(unittest.TestCase):
    def test_run_intervals_have_explicit_defaults(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = load_run_config()

        self.assertEqual(config.collect_interval_seconds, 300)
        self.assertEqual(config.weekly_check_interval_seconds, 86400)
        self.assertEqual(config.monthly_check_interval_seconds, 86400)

    def test_run_intervals_are_configurable_positive_integers(self) -> None:
        environment = {
            "MIKROTIK_COLLECT_INTERVAL_SECONDS": "60",
            "MIKROTIK_WEEKLY_CHECK_INTERVAL_SECONDS": "3600",
            "MIKROTIK_MONTHLY_CHECK_INTERVAL_SECONDS": "7200",
        }
        with patch.dict(os.environ, environment, clear=True):
            config = load_run_config()

        self.assertEqual(config.collect_interval_seconds, 60)
        self.assertEqual(config.weekly_check_interval_seconds, 3600)
        self.assertEqual(config.monthly_check_interval_seconds, 7200)

        for invalid in ("0", "-1", "1.5", ""):
            with (
                self.subTest(invalid=invalid),
                patch.dict(
                    os.environ,
                    {"MIKROTIK_COLLECT_INTERVAL_SECONDS": invalid},
                    clear=True,
                ),
                self.assertRaisesRegex(ValueError, "must be a positive integer"),
            ):
                load_run_config()

    def test_mail_notifier_path_is_explicit(self) -> None:
        with patch.dict(
            os.environ,
            {
                "MIKROTIK_REPORT_TO": "recipient@example.net",
                "MIKROTIK_REPORT_NOTIFIER": "/opt/mail-notifier/send-mail.sh",
            },
            clear=True,
        ):
            config = load_mail_config()

        self.assertEqual(
            config.notifier,
            Path("/opt/mail-notifier/send-mail.sh"),
        )

    def test_mail_notifier_path_must_be_absolute(self) -> None:
        with (
            patch.dict(
                os.environ,
                {
                    "MIKROTIK_REPORT_TO": "recipient@example.net",
                    "MIKROTIK_REPORT_NOTIFIER": "mail-notifier/send-mail.sh",
                },
                clear=True,
            ),
            self.assertRaisesRegex(
                ValueError,
                "MIKROTIK_REPORT_NOTIFIER must be an absolute path",
            ),
        ):
            load_mail_config()


if __name__ == "__main__":
    unittest.main()
