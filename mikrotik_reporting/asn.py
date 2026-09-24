"""Optional ASN lookups using Team Cymru's bulk WHOIS service."""

from __future__ import annotations

import ipaddress
import socket

from .models import ASNMetadata

WHOIS_HOST = "whois.cymru.com"
WHOIS_PORT = 43


def lookup_asns(
    source_ips: list[str], *, timeout_seconds: float = 5.0
) -> dict[str, ASNMetadata]:
    """Resolve IPv4 addresses in one Team Cymru bulk WHOIS request."""
    addresses = sorted({str(ipaddress.IPv4Address(value)) for value in source_ips})
    if not addresses:
        return {}

    request = "begin\nverbose\n" + "\n".join(addresses) + "\nend\n"
    results: dict[str, ASNMetadata] = {}
    with socket.create_connection(
        (WHOIS_HOST, WHOIS_PORT), timeout=timeout_seconds
    ) as connection:
        connection.settimeout(timeout_seconds)
        connection.sendall(request.encode("ascii"))
        with connection.makefile("r", encoding="utf-8", errors="replace") as response:
            for raw_line in response:
                fields = [field.strip() for field in raw_line.split("|")]
                if len(fields) < 7 or fields[0].lower() in ("as", "na"):
                    continue
                try:
                    source_ip = str(ipaddress.IPv4Address(fields[1]))
                except ipaddress.AddressValueError:
                    continue
                if source_ip not in addresses or not fields[0]:
                    continue
                results[source_ip] = {
                    "asn": fields[0],
                    "organization": fields[6],
                }
    return results
