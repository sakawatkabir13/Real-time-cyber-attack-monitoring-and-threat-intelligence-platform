"""Redis-backed aggregation and online scoring of completed traffic windows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
from urllib.parse import urlsplit

from app.config import settings
from app.redis_client import redis_client
from app.services.ml_engine import ml_engine
from app.services.ml_features import temporal_features
from app.services.privacy import hash_ip

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BehavioralFinding:
    scope: str
    attack_type: str
    severity: str
    score: float
    explanation: str
    model_version: str


def _window_start(timestamp: datetime, seconds: int) -> int:
    epoch = int(timestamp.timestamp())
    return epoch - (epoch % seconds)


def _base_key(scope: str, server_hash: str, entity_key: str, start: int) -> str:
    return f"ml:window:{scope}:{server_hash}:{entity_key}:{start}"


def values_from_snapshot(data: dict[str, str], cardinalities: dict[str, int], top: float) -> dict[str, float]:
    count = max(1, int(data.get("request_count", 0)))
    seconds = max(1, int(data.get("window_seconds", 1)))
    values = {
        "request_rate": count / seconds,
        "unique_ips": float(cardinalities.get("unique_ips", 0)),
        "new_ip_ratio": int(data.get("new_ip_count", 0)) / count,
        "unique_paths": float(cardinalities.get("unique_paths", 0)),
        "top_path_share": top / count,
        "status_4xx_ratio": int(data.get("status_4xx", 0)) / count,
        "status_5xx_ratio": int(data.get("status_5xx", 0)) / count,
        "avg_bytes": int(data.get("bytes_total", 0)) / count,
        "avg_request_time": float(data.get("request_time_total", 0.0)) / count,
        "unique_user_agents": float(cardinalities.get("unique_user_agents", 0)),
        "reputation_score": float(data.get("reputation_score", 0.0)),
        "reporter_count": float(data.get("reporter_count", 0)),
        "community_reports": float(data.get("community_reports", 0)),
    }
    values.update(temporal_features(int(data.get("window_start", 0))))
    return values


class BehavioralFeatureService:
    ttl_seconds = 8 * 86_400

    @staticmethod
    async def _snapshot(base: str) -> tuple[dict[str, str], dict[str, int], float] | None:
        client = redis_client._require_client()
        data = await client.hgetall(base)
        if not data:
            return None
        pipe = client.pipeline()
        pipe.pfcount(f"{base}:ips")
        pipe.pfcount(f"{base}:paths")
        pipe.pfcount(f"{base}:uas")
        pipe.zrevrange(f"{base}:path_counts", 0, 0, withscores=True)
        unique_ips, unique_paths, unique_uas, top_paths = await pipe.execute()
        top_count = float(top_paths[0][1]) if top_paths else 0.0
        return (
            data,
            {
                "unique_ips": int(unique_ips),
                "unique_paths": int(unique_paths),
                "unique_user_agents": int(unique_uas),
            },
            top_count,
        )

    async def _score_completed(
        self,
        scope: str,
        base: str,
        minimum_requests: int,
    ) -> BehavioralFinding | None:
        client = redis_client._require_client()
        claim_key = f"ml:score:{base}"
        if not await client.set(claim_key, "1", ex=self.ttl_seconds, nx=True):
            return None
        snapshot = await self._snapshot(base)
        if not snapshot:
            await client.delete(claim_key)
            return None
        data, cardinalities, top_count = snapshot
        request_count = int(data.get("request_count", 0))
        if request_count < minimum_requests:
            return None
        values = values_from_snapshot(data, cardinalities, top_count)
        prediction = ml_engine.score(scope, data["server_id"], values)
        if prediction is None:
            await client.expire(claim_key, 60)
            return None
        await client.hset(
            base,
            mapping={
                "anomaly_score": prediction.score,
                "model_version": prediction.model_version,
                "anomaly_explanation": prediction.explanation,
                "updated_at": datetime.now().timestamp(),
            },
        )
        if int(data.get("rule_threat_count", 0)) > 0:
            return None
        if prediction.score < settings.ML_ALERT_SCORE:
            return None
        attack_type = (
            "server_traffic_anomaly" if scope == "server" else "source_behavior_anomaly"
        )
        return BehavioralFinding(
            scope=scope,
            attack_type=attack_type,
            severity="high" if prediction.score >= 95.0 else "medium",
            score=prediction.score,
            explanation=prediction.explanation,
            model_version=prediction.model_version,
        )

    async def _observe_scope(
        self,
        *,
        scope: str,
        server_id: str,
        source_ip: str,
        timestamp: datetime,
        path: str,
        user_agent: str,
        status_code: int,
        bytes_sent: int,
        request_time: float,
        rule_threat: bool,
        reputation_score: float,
        reporter_count: int,
        community_reports: int,
    ) -> BehavioralFinding | None:
        client = redis_client._require_client()
        seconds = (
            settings.ML_SERVER_WINDOW_SECONDS
            if scope == "server"
            else settings.ML_SOURCE_WINDOW_SECONDS
        )
        minimum = (
            settings.ML_MIN_SERVER_REQUESTS
            if scope == "server"
            else settings.ML_MIN_SOURCE_REQUESTS
        )
        start = _window_start(timestamp, seconds)
        server_hash = hash_ip(f"server:{server_id}")
        entity_key = "server" if scope == "server" else hash_ip(source_ip)
        base = _base_key(scope, server_hash, entity_key, start)
        normalized_path = (urlsplit(path or "/").path or "/")[:512]
        path_hash = hash_ip(f"path:{normalized_path}")
        ua_hash = hash_ip(f"ua:{user_agent or 'unknown'}")
        status_family = min(5, max(1, status_code // 100))

        new_ip = False
        if scope == "server":
            seen_key = f"ml:seen:{server_hash}:{hash_ip(source_ip)}"
            new_ip = bool(await client.set(seen_key, "1", ex=30 * 86_400, nx=True))

        pipe = client.pipeline()
        pipe.hset(
            base,
            mapping={
                "scope": scope,
                "server_id": server_id,
                "entity_key": entity_key,
                "source_ip_hash": entity_key if scope == "source" else "",
                "window_start": start,
                "window_seconds": seconds,
                "updated_at": datetime.now().timestamp(),
                "reputation_score": max(0.0, reputation_score),
                "reporter_count": max(0, reporter_count),
                "community_reports": max(0, community_reports),
            },
        )
        pipe.hincrby(base, "request_count", 1)
        pipe.hincrby(base, "bytes_total", max(0, bytes_sent))
        pipe.hincrbyfloat(base, "request_time_total", max(0.0, request_time))
        pipe.hincrby(base, f"status_{status_family}xx", 1)
        if new_ip:
            pipe.hincrby(base, "new_ip_count", 1)
        if rule_threat:
            pipe.hincrby(base, "rule_threat_count", 1)
        pipe.pfadd(f"{base}:ips", hash_ip(source_ip))
        pipe.pfadd(f"{base}:paths", path_hash)
        pipe.pfadd(f"{base}:uas", ua_hash)
        pipe.zincrby(f"{base}:path_counts", 1, path_hash)
        for key in (base, f"{base}:ips", f"{base}:paths", f"{base}:uas", f"{base}:path_counts"):
            pipe.expire(key, self.ttl_seconds)
        await pipe.execute()

        previous = _base_key(scope, server_hash, entity_key, start - seconds)
        return await self._score_completed(scope, previous, minimum)

    async def observe(
        self,
        *,
        log: object,
        timestamp: datetime,
        rule_threat: bool,
        reputation_score: float,
        reporter_count: int,
        community_reports: int,
    ) -> BehavioralFinding | None:
        findings = []
        for scope in ("server", "source"):
            try:
                finding = await self._observe_scope(
                    scope=scope,
                    server_id=log.server_id,
                    source_ip=log.source_ip,
                    timestamp=timestamp,
                    path=log.path,
                    user_agent=log.user_agent,
                    status_code=log.status_code,
                    bytes_sent=log.bytes_sent,
                    request_time=log.request_time,
                    rule_threat=rule_threat,
                    reputation_score=reputation_score,
                    reporter_count=reporter_count,
                    community_reports=community_reports,
                )
                if finding:
                    findings.append(finding)
            except Exception:
                logger.exception("Behavioral %s-window observation failed", scope)
        return max(findings, key=lambda item: item.score, default=None)


behavioral_features = BehavioralFeatureService()
