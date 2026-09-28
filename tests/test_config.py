import os
import unittest
from datetime import time
from pathlib import Path
from unittest.mock import patch

from mikrotik_reporting.config import load_asn_config, load_mail_config, load_run_config


class ConfigTests(unittest.TestCase):
    def test_asn_enrichment_is_disabled_by_default_and_accepts_booleans(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = load_asn_config()
            self.assertFalse(config.enabled)
            self.assertEqual(config.batch_size, 100)
            self.assertEqual(config.retry_base_seconds, 3600)
            self.assertEqual(config.retry_max_seconds, 86400)
            self.assertEqual(config.refresh_days, 30)

        for value in ("1", "true", "YES", "on"):
            with patch.dict(os.environ, {"MIKROTIK_ASN_ENABLED": value}, clear=True):
                self.assertTrue(load_asn_config().enabled)

        with (
            patch.dict(os.environ, {"MIKROTIK_ASN_ENABLED": "perhaps"}, clear=True),
            self.assertRaisesRegex(
                ValueError, "MIKROTIK_ASN_ENABLED must be a boolean"
            ),
        ):
            load_asn_config()

    def test_asn_hydration_policy_is_configurable_and_validated(self) -> None:
        environment = {
            "MIKROTIK_ASN_ENABLED": "true",
            "MIKROTIK_ASN_BATCH_SIZE": "25",
            "MIKROTIK_ASN_RETRY_BASE_SECONDS": "60",
            "MIKROTIK_ASN_RETRY_MAX_SECONDS": "600",
            "MIKROTIK_ASN_REFRESH_DAYS": "7",
        }
        with patch.dict(os.environ, environment, clear=True):
            config = load_asn_config()
        self.assertEqual(config.batch_size, 25)
        self.assertEqual(config.retry_base_seconds, 60)
        self.assertEqual(config.retry_max_seconds, 600)
        self.assertEqual(config.refresh_days, 7)

        environment["MIKROTIK_ASN_RETRY_MAX_SECONDS"] = "30"
        with (
            patch.dict(os.environ, environment, clear=True),
            self.assertRaisesRegex(ValueError, "must be greater than or equal"),
        ):
            load_asn_config()

    def test_run_schedule_has_explicit_defaults(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            config = load_run_config()

        self.assertEqual(config.collect_interval_seconds, 300)
        self.assertEqual(config.weekly_check_time, time(0, 15))
        self.assertEqual(config.monthly_check_time, time(0, 30))

    def test_run_schedule_is_configurable(self) -> None:
        environment = {
            "MIKROTIK_COLLECT_INTERVAL_SECONDS": "60",
            "MIKROTIK_WEEKLY_CHECK_TIME": "01:25",
            "MIKROTIK_MONTHLY_CHECK_TIME": "23:45",
        }
        with patch.dict(os.environ, environment, clear=True):
            config = load_run_config()

        self.assertEqual(config.collect_interval_seconds, 60)
        self.assertEqual(config.weekly_check_time, time(1, 25))
        self.assertEqual(config.monthly_check_time, time(23, 45))

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

        for name in ("MIKROTIK_WEEKLY_CHECK_TIME", "MIKROTIK_MONTHLY_CHECK_TIME"):
            for invalid in ("", "1:25", "24:00", "12:60", "12:30:00", "abc"):
                with (
                    self.subTest(name=name, invalid=invalid),
                    patch.dict(os.environ, {name: invalid}, clear=True),
                    self.assertRaisesRegex(
                        ValueError, "must be a time in HH:MM format"
                    ),
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
