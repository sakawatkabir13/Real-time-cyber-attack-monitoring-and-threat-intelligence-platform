import asyncio
import json
from typing import Any

from fastapi import WebSocket

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
                await connection.send_text(message)
                return None
            except Exception:
                return connection

        dead = [item for item in await asyncio.gather(*(send(c) for c in connections)) if item]
        if dead:
            async with self._lock:
                self.active_connections = [c for c in self.active_connections if c not in dead]

    async def broadcast_json(self, data: dict[str, Any]):
        await self.broadcast(json.dumps(data))

manager = ConnectionManager()
