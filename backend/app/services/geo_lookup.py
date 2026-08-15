import asyncio
import ipaddress
import os
from collections import OrderedDict

import httpx
from app.config import settings

class GeoLookup:
    def __init__(self):
        self.cache: OrderedDict[str, dict] = OrderedDict()
        self.client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()
        self.reader = None

    async def _client(self) -> httpx.AsyncClient:
        async with self._lock:
            if self.client is None or self.client.is_closed:
                self.client = httpx.AsyncClient(timeout=5.0)
            return self.client

    async def lookup(self, ip: str) -> dict:
        if ip in self.cache:
            self.cache.move_to_end(ip)
            return self.cache[ip]

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        if not address.is_global:
            return {}

        if settings.MAXMIND_DB_PATH and os.path.isfile(settings.MAXMIND_DB_PATH):
            try:
                if self.reader is None:
                    import geoip2.database

                    self.reader = geoip2.database.Reader(settings.MAXMIND_DB_PATH)
                response = self.reader.city(ip)
                result = {
                    "country": response.country.iso_code or "XX",
                    "lat": response.location.latitude,
                    "lon": response.location.longitude,
                }
                self.cache[ip] = result
                return result
            except Exception as exc:
                print(f"MaxMind lookup error for {ip}: {exc}")

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

geo_lookup = GeoLookup()
