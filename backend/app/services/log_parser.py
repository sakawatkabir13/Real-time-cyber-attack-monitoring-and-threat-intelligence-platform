"""Shared collector/upload parser. Preserve event time and missing measurements."""

from datetime import datetime, timezone
import ipaddress
import json
import math
import re
from urllib.parse import urlsplit

from app.config import settings
from app.schemas.ingest import LogEntry


LOG_PATTERN = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+)[^"]*" (\d{3}) (\d+|-)'
    r'(?:\s+"[^"\n]*"\s+"([^"\n]*)")?(?:\s+(rt|rt_us)=([0-9.]+))?\s*$'
)


def parse_timestamp(value: str | int | float) -> datetime:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A request timestamp is required")
    try:
        result = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Request timestamps must include a timezone")
    return result.astimezone(timezone.utc)


def parse_event(event: dict, server_id: str) -> LogEntry | None:
    try:
        if len(json.dumps(event, default=str)) > 16_384:
            return None
        event_id = event.get("event_id")
        raw = event.get("raw_log")
        if isinstance(raw, str):
            # Uploads and collectors accept the same JSON-lines format.
            if raw.lstrip().startswith("{"):
                decoded = json.loads(raw)
                if not isinstance(decoded, dict) or "raw_log" in decoded:
                    return None
                event = decoded
            else:
                match = LOG_PATTERN.fullmatch(raw)
                if not match:
                    return None
                ip, timestamp, method, path, status, size, ua, unit, duration = match.groups()
                if duration is not None and unit == "rt_us":
                    duration = float(duration) / 1_000_000
                event = dict(source_ip=ip, timestamp=timestamp, method=method, path=path,
                             status_code=status, bytes_sent=0 if size == "-" else size,
                             user_agent=ua, request_time=duration)
        timestamp = parse_timestamp(event.get("timestamp"))
        if timestamp.timestamp() > datetime.now(timezone.utc).timestamp() + settings.LOG_MAX_FUTURE_SECONDS:
            return None
        duration = event.get("request_time")
        if duration is None and event.get("request_time_us") is not None:
            duration = float(event["request_time_us"]) / 1_000_000
        if duration in (None, "", "-"):
            duration = None
        else:
            duration = float(duration)
            if not math.isfinite(duration) or duration < 0:
                return None
        status = int(event.get("status_code", 200))
        size = int(event.get("bytes_sent") or 0)
        if not 100 <= status <= 599 or size < 0:
            return None
        raw_ip = event.get("source_ip") or event.get("ip")
        if not isinstance(raw_ip, str):
            return None
        ip = str(ipaddress.ip_address(raw_ip))
        path = str(event.get("path") or "/")[:8192]
        urlsplit(path)  # Reject malformed URL authority syntax before detection.
        return LogEntry(
            server_id=server_id, event_id=event_id,
            timestamp=timestamp.isoformat(), source_ip=ip,
            method=str(event.get("method") or "GET")[:10],
            path=path, status_code=status,
            bytes_sent=size, request_time=duration,
            user_agent=str(event.get("user_agent") or "Unknown")[:2048],
            host=str(event.get("host") or "unknown")[:255],
        )
    except (TypeError, ValueError, OverflowError, OSError):
        return None
