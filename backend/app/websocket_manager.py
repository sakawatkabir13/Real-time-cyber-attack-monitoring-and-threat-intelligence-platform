import asyncio
import json
import logging
import time
from typing import Any

from fastapi import WebSocket

from app.redis_client import redis_client


logger = logging.getLogger(__name__)
WEBSOCKET_EVENT_CHANNEL = "vanguard:websocket-events"
WEBSOCKET_RELAY_HEARTBEAT = "system:websocket-relay:heartbeat"


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
        """Reconnect after Redis outages and report liveness even while idle."""
        backoff = 1.0
        while True:
            pubsub = None
            try:
                client = redis_client._require_client()
                pubsub = client.pubsub()
                await pubsub.subscribe(WEBSOCKET_EVENT_CHANNEL)
                logger.info("WebSocket Redis relay subscribed")
                while True:
                    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=5.0)
                    await client.set(WEBSOCKET_RELAY_HEARTBEAT, str(time.time()), ex=30)
                    backoff = 1.0
                    if not message or message.get("type") != "message":
                        continue
                    payload = message.get("data")
                    if isinstance(payload, bytes):
                        payload = payload.decode("utf-8")
                    if isinstance(payload, str):
                        await self.broadcast(payload)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("WebSocket Redis relay disconnected; retrying in %.0fs", backoff)
            finally:
                if pubsub is not None:
                    try:
                        await pubsub.aclose()
                    except Exception:
                        logger.warning("Could not close WebSocket Redis subscription", exc_info=True)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)

manager = ConnectionManager()
