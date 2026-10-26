"""Create one synthetic alert when known device telemetry becomes silent."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from app.config import Settings
from app.db import Database
from app.schemas.alert import Alert, AlertSource, Device, MitreTechnique, Rule
from app.services.catalog import RulesCatalog


class SilentDeviceWatcher:
    """Detect state transitions to silent without self-refreshing telemetry."""

    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database
        self.catalog = RulesCatalog.from_file(settings.rules_catalog)

    def run_once(self) -> int:
        entry = self.catalog.get("device-silent")
        if entry is None:
            raise RuntimeError("rules catalog is missing device-silent")
        inserted = 0
        for device in self.database.silent_devices(self.settings.device_silent_minutes):
            identity = hashlib.sha256(str(device["device_name"]).encode()).hexdigest()[:24]
            state_key = f"silent_device:{identity}"
            last_seen = str(device["last_seen"])
            if self.database.get_state(state_key) == last_seen:
                continue
            source = (
                AlertSource.WAZUH
                if self.settings.alert_source == AlertSource.WAZUH.value
                else AlertSource.MOCK
            )
            alert = Alert(
                timestamp=datetime.now(UTC),
                source=source,
                device=Device(
                    name=str(device["device_name"]),
                    type=str(device["device_type"]),
                    vendor=device.get("device_vendor"),
                    ip=device.get("device_ip"),
                ),
                severity=entry.default_severity,
                rule=Rule(
                    id="SYSTEM_DEVICE_SILENT",
                    description=entry.description,
                    level=10,
                    groups=list(entry.groups),
                    catalog_id=entry.id,
                ),
                mitre=[
                    MitreTechnique(id=item.id, name=item.name, tactic=item.tactic)
                    for item in entry.mitre
                ],
                tags=["device_silent", "telemetry_health"],
                raw_log=f"No telemetry received since {last_seen}",
            )
            if self.database.insert_alert(alert):
                inserted += 1
            self.database.set_state(state_key, last_seen)
        return inserted
