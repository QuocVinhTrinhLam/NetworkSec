"""Authorization helpers kept separate for easy security testing."""


def is_authorized(chat_id: int | str | None, allowed_chat_ids: set[int]) -> bool:
    """Return False for malformed or unlisted chat IDs without raising."""
    try:
        return int(chat_id) in allowed_chat_ids
    except (TypeError, ValueError):
        return False
