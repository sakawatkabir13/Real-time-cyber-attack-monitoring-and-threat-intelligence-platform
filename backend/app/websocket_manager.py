import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket

from app.redis_client import redis_client


logger = logging.getLogger(__name__)
WEBSOCKET_EVENT_CHANNEL = "vanguard:websocket-events"


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    @property
    def count(self) -> int:
        return len(self.active_connections)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        async with self._lock:
            connections = list(self.active_connections)

        async def send(connection: WebSocket) -> WebSocket | None:
            try:
                await asyncio.wait_for(connection.send_text(message), timeout=5.0)
                return None
            except Exception:
                return connection

        dead = [item for item in await asyncio.gather(*(send(c) for c in connections)) if item]
        if dead:
            async with self._lock:
                self.active_connections = [c for c in self.active_connections if c not in dead]

    async def broadcast_json(self, data: dict[str, Any]):
        await self.broadcast(json.dumps(data))

    async def publish_json(self, data: dict[str, Any]) -> None:
        """Publish an event so the API process can relay it to its sockets."""
        await redis_client._require_client().publish(
            WEBSOCKET_EVENT_CHANNEL,
            json.dumps(data),
        )

    async def relay_published(self) -> None:
        """Relay events from API and Celery processes to local sockets."""
        pubsub = redis_client._require_client().pubsub()
        await pubsub.subscribe(WEBSOCKET_EVENT_CHANNEL)
        try:
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                payload = message.get("data")
                if isinstance(payload, bytes):
                    payload = payload.decode("utf-8")
                if isinstance(payload, str):
                    await self.broadcast(payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("WebSocket Redis relay stopped unexpectedly")
            raise
        finally:
            await pubsub.unsubscribe(WEBSOCKET_EVENT_CHANNEL)
            await pubsub.aclose()

manager = ConnectionManager()
