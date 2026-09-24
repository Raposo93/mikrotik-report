import unittest
from io import StringIO
from unittest.mock import patch

from mikrotik_reporting.asn import lookup_asns


class FakeSocket:
    def __init__(self, response: str) -> None:
        self.response = response
        self.request = b""
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        pass

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendall(self, request: bytes) -> None:
        self.request = request

    def makefile(self, *_args, **_kwargs):
        return StringIO(self.response)


class ASNLookupTests(unittest.TestCase):
    def test_bulk_lookup_parses_results_and_ignores_headers(self) -> None:
        connection = FakeSocket(
            "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n"
            "64496 | 192.0.2.10 | 192.0.2.0/24 | ZZ | test | 2026-01-01 | "
            "Example Network\n"
            "malformed response\n"
        )
        with patch(
            "mikrotik_reporting.asn.socket.create_connection",
            return_value=connection,
        ) as create_connection:
            result = lookup_asns(["192.0.2.10", "192.0.2.10"], timeout_seconds=2)

        self.assertEqual(
            result,
            {"192.0.2.10": {"asn": "64496", "organization": "Example Network"}},
        )
        self.assertEqual(
            connection.request,
            b"begin\nverbose\n192.0.2.10\nend\n",
        )
        self.assertEqual(connection.timeout, 2)
        create_connection.assert_called_once_with(("whois.cymru.com", 43), timeout=2)

    def test_empty_lookup_does_not_open_a_connection(self) -> None:
        with patch("mikrotik_reporting.asn.socket.create_connection") as connection:
            self.assertEqual(lookup_asns([]), {})
        connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
