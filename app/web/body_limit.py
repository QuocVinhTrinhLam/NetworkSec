"""Bound small management requests before decoding their bodies."""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

API_BODY_LIMIT = 4 * 1024 * 1024


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] not in {"POST", "PATCH", "DELETE"}
            or not scope["path"].startswith("/api/v1/")
        ):
            await self.app(scope, receive, send)
            return

        buffered = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(buffered) + len(chunk) > API_BODY_LIMIT:
                await JSONResponse({"detail": "Request body too large"}, 413)(scope, receive, send)
                return
            buffered.extend(chunk)
            if not message.get("more_body", False):
                break
        initial: Message | None = {"type": "http.request", "body": bytes(buffered)}
        buffered.clear()

        async def replay() -> Message:
            nonlocal initial
            if initial is None:
                return await receive()
            message, initial = initial, None
            return message

        await self.app(scope, replay, send)
