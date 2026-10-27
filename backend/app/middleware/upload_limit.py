"""
ASGI middleware that rejects oversized upload bodies *before* they are
parsed or spooled to disk.

* If ``Content-Length`` exceeds the limit → immediate 413.
* For chunked bodies (no Content-Length) the byte count is enforced while
  streaming; the request is aborted with 413 once the limit is crossed.
"""
from __future__ import annotations

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class _BodyTooLarge(Exception):
    pass


class UploadSizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int, path_prefixes: tuple[str, ...]):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.path_prefixes = path_prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST" or not scope["path"].startswith(self.path_prefixes):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                if int(cl) > self.max_body_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send, status=400, detail="Invalid Content-Length")
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise _BodyTooLarge()
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not response_started:
                await self._reject(send)

    @staticmethod
    async def _reject(send: Send, status: int = 413, detail: str = "File exceeds the 25 MB upload limit") -> None:
        body = json.dumps({"detail": detail}).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                        (b"connection", b"close")],
        })
        await send({"type": "http.response.body", "body": body})
