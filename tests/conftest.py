"""Shared test environment that never relies on production credentials."""

from __future__ import annotations

import os

os.environ.setdefault("SESSION_SECRET", "test-only-session-secret-with-32-bytes")
