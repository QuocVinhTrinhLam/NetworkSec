"""Contract shared by every alert source."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.schemas.alert import Alert


class BaseAdapter(ABC):
    """Fetch already-normalized alerts from one source."""

    @abstractmethod
    async def fetch_new_alerts(self) -> list[Alert]:
        """Return alerts observed since the previous successful call."""
