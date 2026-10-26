"""Authorization helpers kept separate for easy security testing."""


def is_authorized(chat_id: int | str | None, allowed_chat_ids: set[int]) -> bool:
    """Return False for malformed or unlisted chat IDs without raising."""
    if isinstance(chat_id, int):
        normalized = chat_id
    elif isinstance(chat_id, str):
        try:
            normalized = int(chat_id)
        except ValueError:
            return False
    else:
        return False
    return normalized in allowed_chat_ids
