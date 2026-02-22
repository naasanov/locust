import asyncio
import dataclasses
import json
import logging
from typing import Any

from fastapi import WebSocket
from pydantic import BaseModel

logger = logging.getLogger(__name__)


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if isinstance(value, dict):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(v) for v in value]
    return value


class WebSocketEventService:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def register(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.add(websocket)
            logger.info("WS client connected (clients=%s)", len(self._clients))

    async def unregister(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)
            logger.info("WS client disconnected (clients=%s)", len(self._clients))

    async def emit(self, message: dict) -> None:
        payload = json.dumps(_to_jsonable(message))
        async with self._lock:
            clients = list(self._clients)

        stale: list[WebSocket] = []
        for client in clients:
            try:
                await client.send_text(payload)
            except Exception:
                stale.append(client)

        if stale:
            async with self._lock:
                for client in stale:
                    self._clients.discard(client)
            logger.warning("Dropped %s stale WS client(s)", len(stale))

    async def ping_all(self) -> None:
        await self.emit({"ping": "alive"})


_WS_EVENT_SERVICE = WebSocketEventService()


def get_ws_event_service() -> WebSocketEventService:
    return _WS_EVENT_SERVICE


async def emit_ws_message(message: dict) -> None:
    await _WS_EVENT_SERVICE.emit(message)
