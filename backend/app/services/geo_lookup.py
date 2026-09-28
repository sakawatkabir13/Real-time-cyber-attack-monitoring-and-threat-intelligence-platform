import asyncio
import ipaddress
import logging
import os
from collections import OrderedDict

import httpx
from app.config import settings

logger = logging.getLogger(__name__)

class GeoLookup:
    def __init__(self):
        self.cache: OrderedDict[str, dict] = OrderedDict()
        self.client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()
        self.reader = None
        self._reader_mtime_ns: int | None = None

    def _refresh_reader(self) -> None:
        path = settings.MAXMIND_DB_PATH
        try:
            mtime = os.stat(path).st_mtime_ns if path else None
        except FileNotFoundError:
            mtime = None
        except OSError:
            logger.warning("Could not inspect MaxMind database", exc_info=True)
            return
        if mtime == self._reader_mtime_ns and (mtime is None or self.reader is not None):
            return
        if mtime is None:
            if self.reader is not None:
                self.reader.close()
            self.reader = None
            self._reader_mtime_ns = None
            self.cache.clear()
            return
        try:
            import geoip2.database
            replacement = geoip2.database.Reader(path)
        except Exception:
            logger.warning("Could not load MaxMind database", exc_info=True)
            return
        previous = self.reader
        self.reader = replacement
        self._reader_mtime_ns = mtime
        self.cache.clear()
        if previous is not None:
            previous.close()

    async def _client(self) -> httpx.AsyncClient:
        async with self._lock:
            if self.client is None or self.client.is_closed:
                self.client = httpx.AsyncClient(timeout=5.0)
            return self.client

    async def lookup(self, ip: str) -> dict:
        self._refresh_reader()
        if ip in self.cache:
            self.cache.move_to_end(ip)
            return self.cache[ip]

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        if not address.is_global:
            return {}

        if self.reader is not None:
            try:
                response = self.reader.city(ip)
                result = {
                    "country": response.country.iso_code or "XX",
                    "lat": response.location.latitude,
                    "lon": response.location.longitude,
                }
                self.cache[ip] = result
                if len(self.cache) > 10_000:
                    self.cache.popitem(last=False)
                return result
            except Exception:
                logger.warning("MaxMind lookup failed for %s", ip, exc_info=True)

        try:
            client = await self._client()
            resp = await client.get(f"https://get.geojs.io/v1/ip/geo/{ip}.json")
            if resp.status_code == 200:
                data = resp.json()
                latitude = data.get("latitude")
                longitude = data.get("longitude")
                result = {
                    "country": data.get("country_code", "XX"),
                    "lat": float(latitude) if latitude not in (None, "") else None,
                    "lon": float(longitude) if longitude not in (None, "") else None,
                }
                self.cache[ip] = result
                if len(self.cache) > 10_000:
                    self.cache.popitem(last=False)
                return result
        except Exception as e:
            print(f"GeoJS error for {ip}: {e}")

        return {}

    async def close(self) -> None:
        if self.client and not self.client.is_closed:
            await self.client.aclose()
        self.client = None
        if self.reader is not None:
            self.reader.close()
            self.reader = None
        self._reader_mtime_ns = None

geo_lookup = GeoLookup()
