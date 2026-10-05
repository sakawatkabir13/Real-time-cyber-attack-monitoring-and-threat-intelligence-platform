import asyncio
import ipaddress
import json
import logging
from pathlib import Path
import shutil
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import AsyncSessionLocal, engine, get_db
from app.models import CollectorAgent, DdosAlert, MlModelRun, ThreatEvent, TrafficWindow
from app.redis_client import redis_client
from app.routers.ingest import router as ingest_router
from app.routers.alerts import router as alerts_router
from app.routers.collectors import router as collectors_router
from app.routers.incidents import router as incidents_router
from app.security import (
    SESSION_COOKIE,
    client_identifier,
    create_session_token,
    is_valid_session,
    require_dashboard_auth,
    verify_dashboard_password,
    websocket_is_authenticated,
)
from app.services.abuseipdb import check_ip_abuse
from app.services.event_pipeline import serialize_event
from app.services.geo_lookup import geo_lookup
from app.services.ml_engine import ml_engine
from app.services.training_data import training_query, select_training_candidates
from app.websocket_manager import WEBSOCKET_RELAY_HEARTBEAT, manager
from app.services.window_scoring import scoring_loop
from app.services.incident_grouping import grouping_loop
from app.tasks.analyze_logs import (
    ACTIVE_ANALYSIS_KEY,
    LATEST_ANALYSIS_KEY,
    analyze_log_file_task,
    analysis_status_key,
    release_active_analysis,
    save_analysis_status,
)
from app.tasks.health import CELERY_PIPELINE_HEARTBEAT

logger = logging.getLogger(__name__)


def _is_recent(value: str | None, maximum_age: float) -> bool:
    if not value:
        return False
    try:
        return time.time() - float(value) <= maximum_age
    except (TypeError, ValueError):
        return False


def _model_is_fresh(status_payload: dict) -> bool | None:
    if status_payload.get("state") != "ready":
        return None
    try:
        trained_at = datetime.fromisoformat(str(status_payload["trained_at"]))
        if trained_at.tzinfo is None:
            trained_at = trained_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - trained_at <= timedelta(days=2)
    except (KeyError, TypeError, ValueError):
        return False


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_production_secrets()
    await redis_client.connect()
    workers = [asyncio.create_task(scoring_loop(), name="completed-window-scoring"),
               asyncio.create_task(grouping_loop(), name="related-incident-grouping"),
               asyncio.create_task(manager.relay_published(), name="websocket-event-relay")]
    try:
        yield
    finally:
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await geo_lookup.close()
        await redis_client.close()
        await engine.dispose()


app = FastAPI(
    title="Vanguard-360 API",
    lifespan=lifespan,
    docs_url=None if settings.ENVIRONMENT.lower() == "production" else "/docs",
    redoc_url=None if settings.ENVIRONMENT.lower() == "production" else "/redoc",
    openapi_url=None if settings.ENVIRONMENT.lower() == "production" else "/openapi.json",
)
app.include_router(ingest_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(collectors_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class AIAnalysisRequest(BaseModel):
    ip: str = Field(min_length=2, max_length=45)


@app.post("/api/auth/login")
async def login(payload: LoginRequest, request: Request, response: Response):
    identity = client_identifier(request)
    if not await redis_client.allow_request("login", identity, limit=10, window_size=300):
        raise HTTPException(429, "Too many login attempts")
    if not verify_dashboard_password(payload.password):
        raise HTTPException(401, "Invalid password")
    response.set_cookie(
        SESSION_COOKIE,
        create_session_token(),
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        max_age=settings.SESSION_TTL_SECONDS,
        path="/",
    )
    return {"authenticated": True}


@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"authenticated": False}


@app.get("/api/auth/status")
async def auth_status(request: Request):
    return {"authenticated": is_valid_session(request.cookies.get(SESSION_COOKIE))}


@app.get("/api/health")
async def health():
    checks = {"redis": False, "database": False}
    heartbeats: list[str | None] = [None, None, None, None]
    collector_fresh = False
    try:
        checks["redis"] = await redis_client.ping()
        heartbeats = await redis_client._require_client().mget(
            "ml:scorer:heartbeat",
            "incidents:grouper:heartbeat",
            CELERY_PIPELINE_HEARTBEAT,
            WEBSOCKET_RELAY_HEARTBEAT,
        )
    except Exception:
        logger.exception("Redis health check failed")
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
            checks["database"] = True
            latest_collector = await db.scalar(select(func.max(CollectorAgent.last_seen)))
            if latest_collector is not None:
                if latest_collector.tzinfo is None:
                    latest_collector = latest_collector.replace(tzinfo=timezone.utc)
                collector_fresh = latest_collector >= datetime.now(timezone.utc) - timedelta(
                    seconds=settings.COLLECTOR_OFFLINE_SECONDS
                )
    except Exception:
        logger.exception("Database health check failed")
    healthy = all(checks.values())
    model_status = ml_engine.status()
    disk = shutil.disk_usage("/")
    payload = {
        "status": "ok" if healthy else "degraded",
        "checks": checks,
        # These are diagnostic signals, not startup dependencies. Celery cannot
        # emit its first heartbeat until the backend is healthy and starts it.
        "background": {
            "websocketRelay": _is_recent(heartbeats[3], 30),
            "diskUsedPercent": round(100 * disk.used / disk.total, 1),
            "windowScorer": _is_recent(
                heartbeats[0], max(120, settings.ML_SCORING_INTERVAL_SECONDS * 3)
            ),
            "incidentGrouping": _is_recent(
                heartbeats[1], max(180, settings.INCIDENT_GROUPING_INTERVAL_SECONDS * 3)
            ),
            "celeryBeatWorker": _is_recent(heartbeats[2], 120),
            "modelState": model_status.get("state", "warming_up"),
            "modelFresh": _model_is_fresh(model_status),
            "collectorFresh": collector_fresh,
        },
    }
    return payload if healthy else JSONResponse(status_code=503, content=payload)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if not websocket_is_authenticated(websocket):
        await websocket.close(code=4401)
        return
    if manager.count >= settings.MAX_WEBSOCKET_CONNECTIONS:
        await websocket.close(code=1013)
        return
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)


@app.get("/api/events", dependencies=[Depends(require_dashboard_auth)])
async def get_events(
    limit: int = Query(default=100, ge=1, le=500),
    ml_only: bool = False,
    db: AsyncSession = Depends(get_db),
    hours: int | None = Query(default=None, ge=1, le=168),
    server_id: str | None = None,
    source_ip: str | None = None,
    attack_type: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
):
    query = select(ThreatEvent)
    # Plain defaults also support direct calls in diagnostic/unit tests.
    if isinstance(hours, int):
        query = query.where(ThreatEvent.timestamp >= datetime.now(timezone.utc) - timedelta(hours=hours))
    for column, value in ((ThreatEvent.server_id, server_id), (ThreatEvent.source_ip, source_ip), (ThreatEvent.attack_type, attack_type)):
        if value:
            query = query.where(column == value)
    for value in (since, until):
        if value is not None and value.tzinfo is None:
            raise HTTPException(422, "Time filters must include a timezone")
    if since:
        query = query.where(ThreatEvent.timestamp >= since)
    if until:
        query = query.where(ThreatEvent.timestamp < until)
    if ml_only:
        query = query.where(ThreatEvent.attack_type.in_((
            "server_traffic_anomaly", "source_behavior_anomaly"
        )))
    result = await db.execute(
        query.order_by(desc(ThreatEvent.timestamp)).limit(limit)
    )
    return [serialize_event(event) for event in result.scalars()]


@app.get("/api/stats", dependencies=[Depends(require_dashboard_auth)])
async def get_stats(db: AsyncSession = Depends(get_db), hours: int | None = Query(default=None, ge=1, le=168), server_id: str | None = None):
    client = redis_client._require_client()
    period = hours if isinstance(hours, int) else 24
    scoped = isinstance(hours, int)
    cache_key = f"dashboard:stats:{period}:{server_id or '*'}:{scoped}"
    cached = await client.get(cache_key)
    if cached:
        return json.loads(cached)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=period)
    minute_ago = now - timedelta(minutes=1)
    event_filters = [ThreatEvent.server_id == server_id] if server_id else []
    summary_filters = event_filters + ([ThreatEvent.timestamp >= cutoff, ThreatEvent.timestamp < now] if scoped else [])
    alert_filters = [DdosAlert.server_id == server_id] if server_id else []
    if scoped:
        alert_filters += [DdosAlert.last_seen >= cutoff, DdosAlert.last_seen < now]
    total_result = await db.execute(select(func.count(ThreatEvent.id)).where(*summary_filters))
    ips_result = await db.execute(select(func.count(func.distinct(ThreatEvent.source_ip))).where(*summary_filters))
    critical_result = await db.execute(
        select(func.count(DdosAlert.id)).where(
            DdosAlert.severity == "critical", DdosAlert.status == "new", *alert_filters
        )
    )
    types_result = await db.execute(
        select(ThreatEvent.attack_type, func.count(ThreatEvent.id))
        .where(ThreatEvent.timestamp >= cutoff, ThreatEvent.timestamp < now, *event_filters)
        .group_by(ThreatEvent.attack_type)
        .order_by(desc(func.count(ThreatEvent.id)))
    )
    bucket_seconds = 300 if period == 1 else 3600 if period <= 24 else 21600
    bucket_count = period * 3600 // bucket_seconds
    hour_bin = func.date_bin(text(f"INTERVAL '{bucket_seconds} seconds'"), ThreatEvent.timestamp, cutoff)
    hour_result = await db.execute(
        select(hour_bin.label("hour_bin"), func.count(ThreatEvent.id))
        .where(ThreatEvent.timestamp >= cutoff, ThreatEvent.timestamp < now, *event_filters)
        .group_by("hour_bin")
        .order_by("hour_bin")
    )
    recent_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(
            ThreatEvent.timestamp >= minute_ago, ThreatEvent.timestamp < now, *event_filters
        )
    )

    counts: dict[int, int] = {}
    for hour, count in hour_result.all():
        if hour:
            normalized = hour.replace(tzinfo=hour.tzinfo or timezone.utc).astimezone(timezone.utc)
            index = int((normalized - cutoff).total_seconds() // bucket_seconds)
            if 0 <= index < bucket_count:
                counts[index] = count
    hourly = [
        {"hour": (cutoff + timedelta(seconds=index * bucket_seconds)).isoformat(), "count": counts.get(index, 0)}
        for index in range(bucket_count)
    ]
    type_counts = [
        {"type": attack_type or "unknown", "count": count}
        for attack_type, count in types_result.all()
    ]
    top_types = type_counts[:5]
    if len(type_counts) > 5:
        top_types.append({"type": "other", "count": sum(row["count"] for row in type_counts[5:])})

    payload = {
        "totalThreats": total_result.scalar() or 0,
        "attacksPerSecond": round((recent_result.scalar() or 0) / 60.0, 2),
        "criticalAlerts": critical_result.scalar() or 0,
        "uniqueIPs": ips_result.scalar() or 0,
        "topAttackTypes": top_types,
        "threatsByHour": hourly,
        "periodHours": period,
        "bucketSeconds": bucket_seconds,
        "capturedAt": now.isoformat(),
    }
    await client.setex(cache_key, 5, json.dumps(payload))
    return payload


@app.get("/api/ml/status", dependencies=[Depends(require_dashboard_auth)])
async def ml_status(db: AsyncSession = Depends(get_db)):
    eligible_by_scope: dict[str, dict[str, int]] = {}
    diagnostics = {}
    for scope, minimum_requests in (
        ("server", settings.ML_MIN_SERVER_REQUESTS),
        ("source", settings.ML_MIN_SOURCE_REQUESTS),
    ):
        server_ids = list((await db.scalars(select(TrafficWindow.server_id).where(TrafficWindow.scope == scope).distinct())).all())
        eligible_by_scope[scope] = {}
        diagnostics[scope] = {}
        for server_id in server_ids:
            candidates = list((await db.scalars(training_query(scope, server_id))).all())
            selected, scanner_excluded = select_training_candidates(candidates, scope)
            eligible_by_scope[scope][server_id] = len(selected)
            cutoff = datetime.now(timezone.utc) - timedelta(days=settings.ML_TRAINING_DAYS)
            totals = (await db.execute(select(
                func.count(TrafficWindow.id),
                func.count(TrafficWindow.id).filter(TrafficWindow.is_training_eligible.is_(True), TrafficWindow.rule_threat_count == 0, TrafficWindow.request_count < minimum_requests),
                func.count(TrafficWindow.id).filter((TrafficWindow.is_training_eligible.is_(False)) | (TrafficWindow.rule_threat_count > 0)),
            ).where(TrafficWindow.scope == scope, TrafficWindow.server_id == server_id, TrafficWindow.feature_schema == 3, TrafficWindow.window_start >= cutoff))).one()
            diagnostics[scope][server_id] = {"totalWindows": totals[0], "tooSparse": totals[1], "ruleExcluded": totals[2], "scannerExcluded": scanner_excluded, "eligible": len(selected), "minimumRequests": minimum_requests}
    run_result = await db.execute(
        select(MlModelRun).order_by(desc(MlModelRun.trained_at)).limit(6)
    )
    payload = ml_engine.status()
    payload["eligibleWindows"] = {
        scope: sum(server_counts.values())
        for scope, server_counts in eligible_by_scope.items()
    }
    payload["eligibleWindowsByServer"] = eligible_by_scope
    payload["minimumTrainingWindows"] = settings.ML_MIN_TRAINING_WINDOWS
    payload["trainingDays"] = settings.ML_TRAINING_DAYS
    payload["trafficWindowSeconds"] = {"server": settings.ML_SERVER_WINDOW_SECONDS, "source": settings.ML_SOURCE_WINDOW_SECONDS}
    payload["trainingScheduleUtc"] = "Daily at 03:30 UTC"
    payload["trainingDiagnostics"] = diagnostics
    payload["featureSchema"] = 3
    scorer, grouper, celery_pipeline = await redis_client._require_client().mget(
        "ml:scorer:heartbeat",
        "incidents:grouper:heartbeat",
        CELERY_PIPELINE_HEARTBEAT,
    )
    payload["scorerLastSeen"] = scorer
    payload["grouperLastSeen"] = grouper
    payload["celeryPipelineLastSeen"] = celery_pipeline
    payload["modelFresh"] = _model_is_fresh(payload)
    latest_collector = await db.scalar(select(func.max(CollectorAgent.last_seen)))
    payload["collectorLastSeen"] = latest_collector.isoformat() if latest_collector else None
    payload["recentRuns"] = [
        {
            "scope": run.scope,
            "serverId": run.server_id,
            "status": run.status,
            "samples": run.sample_count,
            "trainedAt": run.trained_at.isoformat() if run.trained_at else None,
            "error": run.error,
        }
        for run in run_result.scalars()
    ]
    return payload


async def _cached_abuse_lookup(ip: str) -> dict:
    client = redis_client._require_client()
    cache_key = f"abuse:lookup:{ip}"
    cached = await client.get(cache_key)
    if cached:
        return json.loads(cached)
    result = await check_ip_abuse(ip)
    if result.get("available"):
        await client.setex(cache_key, 3600, json.dumps(result))
    return result


@app.post("/api/analyze-log-file", dependencies=[Depends(require_dashboard_auth)])
async def analyze_log_file(file: UploadFile = File(...)):
    content = await file.read(settings.MAX_LOG_SIZE_BYTES + 1)
    await file.close()
    if len(content) > settings.MAX_LOG_SIZE_BYTES:
        raise HTTPException(413, "Log file too large")
    total = sum(
        1 for line in content.decode("utf-8", errors="ignore").splitlines() if line.strip()
    )
    if total == 0:
        raise HTTPException(422, "Log file contains no non-empty lines")

    client = redis_client._require_client()
    active_job = await client.get(ACTIVE_ANALYSIS_KEY)
    if active_job:
        active_raw = await client.get(analysis_status_key(active_job))
        try:
            active_status = json.loads(active_raw) if active_raw else {}
        except json.JSONDecodeError:
            active_status = {}
        if active_status.get("state") in {"queued", "running"}:
            raise HTTPException(409, "A log analysis is already running")
        await client.delete(ACTIVE_ANALYSIS_KEY)

    job_id = uuid.uuid4().hex
    if not await client.set(ACTIVE_ANALYSIS_KEY, job_id, nx=True, ex=86_400):
        raise HTTPException(409, "A log analysis is already running")
    upload_dir = Path(settings.ANALYSIS_UPLOAD_DIR).resolve()
    path = upload_dir / f"{job_id}.log"
    try:
        upload_dir.mkdir(parents=True, exist_ok=True)
        # The upload is already bounded and resident in memory. A direct write
        # avoids leaving an executor job behind if the API process shuts down.
        path.write_bytes(content)
        await save_analysis_status(
            job_id,
            state="queued",
            processed=0,
            total=total,
            rejected=0,
            error=None,
        )
        analyze_log_file_task.delay(job_id, str(path), total)
    except Exception as exc:
        path.unlink(missing_ok=True)
        await save_analysis_status(
            job_id,
            state="error",
            processed=0,
            total=total,
            rejected=0,
            error="Could not queue log analysis",
        )
        await release_active_analysis(job_id)
        logger.exception("Could not queue uploaded log analysis")
        raise HTTPException(503, "Could not queue log analysis") from exc
    return {"status": "Analysis queued", "jobId": job_id, "lines": total}


@app.get("/api/analysis-status", dependencies=[Depends(require_dashboard_auth)])
async def analysis_status(job_id: str | None = Query(default=None, pattern=r"^[a-f0-9]{32}$")):
    raw = await redis_client._require_client().get(analysis_status_key(job_id) if isinstance(job_id, str) else LATEST_ANALYSIS_KEY)
    if not raw:
        if isinstance(job_id, str):
            raise HTTPException(404, "Analysis job not found or expired (retained for 7 days)")
        return {"state": "idle", "processed": 0, "total": 0, "rejected": 0}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.error("Latest analysis status contains invalid JSON")
        return {"state": "error", "processed": 0, "total": 0, "rejected": 0,
                "error": "Stored analysis status is invalid"}


@app.get("/api/ip-lookup/{ip}", dependencies=[Depends(require_dashboard_auth)])
async def get_ip_lookup(ip: str, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(422, "Invalid IP address") from exc
    if not await redis_client.allow_request(
        "ip_lookup", client_identifier(request), limit=30, window_size=60
    ):
        raise HTTPException(429, "IP lookup rate limit exceeded")

    result = await db.execute(
        select(ThreatEvent)
        .where(ThreatEvent.source_ip == normalized_ip)
        .order_by(desc(ThreatEvent.timestamp))
        .limit(50)
    )
    threats = list(result.scalars())
    count_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(ThreatEvent.source_ip == normalized_ip)
    )
    total_attacks = count_result.scalar() or 0
    profile = None
    if total_attacks:
        attack_types: dict[str, int] = {}
        for threat in threats:
            attack_types[threat.attack_type or "unknown"] = attack_types.get(
                threat.attack_type or "unknown", 0
            ) + 1
        profile = {
            "ip": normalized_ip,
            "score": 100 if total_attacks > 10 else 50,
            "total_attacks": total_attacks,
            "country": threats[0].source_country if threats else "Unknown",
            "attack_types": attack_types,
        }

    abuse_data = await _cached_abuse_lookup(normalized_ip)
    return {
        "profile": profile,
        "threats": [
            {
                "id": str(threat.id),
                "ip": threat.source_ip,
                "port": None,
                "event": serialize_event(threat),
                "type": threat.attack_type,
                "severity": threat.severity,
                "created_at": threat.timestamp.isoformat() if threat.timestamp else None,
            }
            for threat in threats
        ],
        "abuseData": abuse_data,
        "lookedUpAt": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/analyze-threat", dependencies=[Depends(require_dashboard_auth)])
async def analyze_threat(req: AIAnalysisRequest, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        normalized_ip = str(ipaddress.ip_address(req.ip))
    except ValueError as exc:
        raise HTTPException(422, "Invalid IP address") from exc
    if not await redis_client.allow_request(
        "ai_analysis", client_identifier(request), limit=5, window_size=60
    ):
        raise HTTPException(429, "AI analysis rate limit exceeded")
    if not settings.GROQ_API_KEY or settings.GROQ_API_KEY == "your_groq_api_key_here":
        raise HTTPException(503, "Groq analysis is not configured")

    result = await db.execute(
        select(ThreatEvent)
        .where(ThreatEvent.source_ip == normalized_ip)
        .order_by(desc(ThreatEvent.timestamp))
        .limit(10)
    )
    threats = list(result.scalars())
    abuse = await _cached_abuse_lookup(normalized_ip)
    attack_types: dict[str, int] = {}
    for threat in threats:
        key = threat.attack_type or "unknown"
        attack_types[key] = attack_types.get(key, 0) + 1
    prompt = (
        "Analyze this IP for security risk using only the supplied facts. "
        "Write at most three concise paragraphs and recommend defensive actions.\n"
        f"IP: {normalized_ip}\nLocal threat count: {len(threats)}\n"
        f"Local attack types: {attack_types}\nAbuseIPDB: {json.dumps(abuse)[:5000]}"
    )
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
                json={
                    "model": settings.GROQ_MODEL,
                    "messages": [
                        {"role": "system", "content": "You are a senior cybersecurity analyst."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 800,
                },
            )
            response.raise_for_status()
            analysis = response.json()["choices"][0]["message"]["content"]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        logger.warning("Groq analysis failed: %s", exc)
        raise HTTPException(503, "AI analysis provider is unavailable") from exc
    return {"analysis": analysis}
