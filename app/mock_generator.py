"""Generate realistic alerts without requiring the network lab or Wazuh."""

from __future__ import annotations

import argparse
import itertools
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from app.config import get_settings
from app.db import Database
from app.services.catalog import RulesCatalog, SeverityMapper
from app.services.normalizer import normalize_alert

MOCK_EVENTS: list[dict[str, Any]] = [
    {
        "rule": {
            "id": "100201",
            "level": 10,
            "description": "Port scan detected",
            "groups": ["port_scan"],
        },
        "agent": {"name": "edge-pfsense"},
        "decoder": {"name": "pfsense"},
        "data": {"srcip": "203.0.113.45", "dstip": "10.0.10.20"},
        "full_log": "filterlog: blocked TCP scan from 203.0.113.45",
    },
    {
        "rule": {
            "id": "100210",
            "level": 13,
            "description": "Repeated SSH authentication failures",
            "groups": ["authentication_failed", "brute_force"],
        },
        "agent": {"name": "core-router"},
        "decoder": {"name": "mikrotik"},
        "data": {"srcip": "198.51.100.23", "dstip": "10.0.99.1", "srcuser": "admin"},
        "full_log": "login failure for user admin from 198.51.100.23 via ssh",
    },
    {
        "rule": {
            "id": "100220",
            "level": 7,
            "description": "Administrator login succeeded",
            "groups": ["admin_login"],
        },
        "agent": {"name": "access-switch-01"},
        "decoder": {"name": "cisco-ios"},
        "data": {"srcip": "10.0.99.10", "dstuser": "netadmin"},
        "full_log": "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: netadmin]",
    },
    {
        "rule": {
            "id": "100230",
            "level": 12,
            "description": "Network device configuration changed",
            "groups": ["config_changed"],
        },
        "agent": {"name": "core-router"},
        "decoder": {"name": "vyos"},
        "data": {"srcip": "10.0.99.10", "user": "netadmin"},
        "full_log": "commit: configuration changed by netadmin",
    },
    {
        "rule": {
            "id": "100240",
            "level": 8,
            "description": "Interface state flapping",
            "groups": ["interface_flap"],
        },
        "agent": {"name": "access-switch-01"},
        "decoder": {"name": "cisco-ios"},
        "full_log": "%LINK-3-UPDOWN: Interface Gi0/2 changed state to down",
    },
    {
        "rule": {
            "id": "100250",
            "level": 13,
            "description": "Port security violation",
            "groups": ["port_security"],
        },
        "agent": {"name": "access-switch-01"},
        "decoder": {"name": "cisco-ios"},
        "data": {"srcip": "10.0.10.77"},
        "full_log": "%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation on Gi0/4",
    },
    {
        "rule": {
            "id": "100260",
            "level": 13,
            "description": "Possible VLAN hopping attempt",
            "groups": ["vlan_hopping"],
        },
        "agent": {"name": "access-switch-01"},
        "decoder": {"name": "openvswitch"},
        "data": {"srcip": "10.0.10.66"},
        "full_log": "unexpected double-tagged 802.1Q frame on access port",
    },
    {
        "rule": {
            "id": "100270",
            "level": 15,
            "description": "SYN flood threshold exceeded",
            "groups": ["dos", "syn_flood"],
        },
        "agent": {"name": "edge-pfsense"},
        "decoder": {"name": "pfsense"},
        "data": {"srcip": "203.0.113.99", "dstip": "10.0.20.10"},
        "full_log": "synproxy: excessive SYN rate from 203.0.113.99",
    },
    {
        "rule": {
            "id": "100280",
            "level": 12,
            "description": "VPN login from unusual source",
            "groups": ["vpn_anomaly"],
        },
        "agent": {"name": "edge-pfsense"},
        "decoder": {"name": "openvpn"},
        "data": {"srcip": "192.0.2.88", "srcuser": "student"},
        "full_log": "openvpn: unusual login location for student",
    },
]


def generate(count: int, interval: float, duplicate_every: int = 0) -> int:
    """Insert fake Wazuh alerts and return the number of new database rows."""
    settings = get_settings()
    database = Database(settings.database_path)
    database.initialize()
    mapper = SeverityMapper.from_file(settings.severity_config)
    catalog = RulesCatalog.from_file(settings.rules_catalog)
    inserted = 0
    previous: dict[str, Any] | None = None
    for index, template in zip(range(count), itertools.cycle(MOCK_EVENTS)):
        event = {**template, "@timestamp": datetime.now(UTC).isoformat(timespec="milliseconds")}
        if duplicate_every and previous is not None and index % duplicate_every == 0:
            event = {**previous, "@timestamp": event["@timestamp"]}
        alert = normalize_alert(event, mapper, catalog, external_id=f"mock-{uuid.uuid4()}")
        inserted += int(database.insert_alert(alert))
        previous = template
        if interval:
            time.sleep(interval)
    return inserted


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=9)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--duplicate-every", type=int, default=0)
    args = parser.parse_args()
    inserted = generate(max(0, args.count), max(0, args.interval), max(0, args.duplicate_every))
    print(f"Inserted {inserted} mock alerts")


if __name__ == "__main__":
    main()
