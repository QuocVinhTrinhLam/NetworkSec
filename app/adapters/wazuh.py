"""Phase 2 Wazuh adapter boundary."""

from app.adapters.base import BaseAdapter
from app.schemas.alert import Alert


class WazuhAdapter(BaseAdapter):
    """Reserved for the Phase 2 OpenSearch integration.

    The implementation will query ``wazuh-alerts-*`` in ascending event-time
    order, use ``search_after`` with ``@timestamp`` and ``_id`` as a durable
    cursor, normalize every hit to :class:`Alert`, and advance the cursor only
    after the validated alerts are committed.
    """

    async def fetch_new_alerts(self) -> list[Alert]:
        raise NotImplementedError(
            "ALERT_SOURCE=wazuh is planned for Phase 2; use ALERT_SOURCE=mock for Phase 1"
        )
