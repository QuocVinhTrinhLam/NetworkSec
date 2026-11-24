"""Export the operational API from the actual route declarations."""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI

from app.config import BASE_DIR, Settings
from app.services.correlation import load_correlation_config
from app.services.topology import TopologyInventory
from app.storage.loki import LokiLogStorage
from app.storage.unavailable import UnavailableAlertStorage
from app.web.api import create_api_router
from app.web.backend import create_backend_router


def build_spec() -> dict[str, Any]:
    app = FastAPI(title="NetworkSec Operational API", version="1.0")
    settings = Settings()
    logs = LokiLogStorage("http://127.0.0.1:3100")
    correlation = load_correlation_config(BASE_DIR / "config" / "correlation_rules.yaml")
    app.include_router(create_api_router(logs, UnavailableAlertStorage()))
    app.include_router(create_backend_router(logs, settings, correlation, TopologyInventory()))
    return app.openapi()


if __name__ == "__main__":
    (BASE_DIR / "docs" / "openapi.json").write_text(
        json.dumps(build_spec(), indent=2) + "\n", encoding="utf-8", newline="\n"
    )
