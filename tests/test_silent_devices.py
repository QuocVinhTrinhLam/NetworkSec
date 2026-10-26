from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.config import BASE_DIR, Settings
from app.db import Database
from app.models import Alert
from app.services.silent_devices import SilentDeviceWatcher


def test_silent_device_alert_is_emitted_once_until_new_telemetry(tmp_path: Path) -> None:
    settings = Settings(
        database_path=tmp_path / "silent.db",
        rules_catalog=BASE_DIR / "config" / "rules_catalog.yaml",
        device_silent_minutes=15,
    )
    database = Database(settings.database_path)
    database.initialize()
    old = datetime.now(UTC) - timedelta(minutes=20)
    database.insert_alert(
        Alert(
            timestamp=old,
            source="mock",
            device={"name": "edge-fw-01", "type": "firewall"},
            severity="medium",
            rule={"id": "100240", "description": "Interface flapping", "level": 6},
            raw_log="link down",
        )
    )
    watcher = SilentDeviceWatcher(settings, database)

    assert watcher.run_once() == 1
    assert watcher.run_once() == 0
    rows = database.list_alerts(limit=10)
    assert sum(row["rule_id"] == "SYSTEM_DEVICE_SILENT" for row in rows) == 1
