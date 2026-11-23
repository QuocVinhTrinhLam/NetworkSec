"""Types for durable OSPF Telegram delivery."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from app.schemas.correlation import OspfAdjacencyKey
from app.schemas.event import EventSeverity


class OspfNotificationKind(StrEnum):
    DOWN = "down"
    RECOVERED = "recovered"
    RECOVERY_RETRACTED = "recovery_retracted"
    ACKNOWLEDGED = "acknowledged"
    OPERATOR_RESOLVED = "operator_resolved"
    OPERATOR_REOPENED = "operator_reopened"
    SUPERSEDED = "superseded"


DeliveryResult = Literal["pending", "delivered", "skipped", "uncertain"]


@dataclass(frozen=True, slots=True)
class OspfNotification:
    notification_id: int
    aggregate_id: str
    chat_id: int
    claim_token: UUID
    message_id: int | None
    kind: OspfNotificationKind
    occurred_at: datetime
    first_seen: datetime
    adjacency: OspfAdjacencyKey
    severity: EventSeverity
    actor: str | None


class TelegramSendDeferred(Exception):
    """Telegram explicitly rejected a first send with a rate-limit response."""

    def __init__(self, retry_after: float) -> None:
        super().__init__("Telegram rate limited the send")
        self.retry_after = retry_after
