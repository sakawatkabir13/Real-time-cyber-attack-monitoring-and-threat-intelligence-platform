import asyncio
import ipaddress
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import (
    BackgroundTasks,
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
from app.models import DdosAlert, MlModelRun, ThreatEvent, TrafficWindow
from app.redis_client import redis_client
from app.routers.ingest import parse_event, router as ingest_router
from app.routers.alerts import router as alerts_router
from app.routers.collectors import router as collectors_router
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
from app.services.detection_engine import detection_engine
from app.services.event_pipeline import PendingThreat, persist_threats, serialize_event
from app.services.geo_lookup import geo_lookup
from app.services.ml_engine import ml_engine
from app.websocket_manager import manager

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_production_secrets()
    await redis_client.connect()
    try:
        yield
    finally:
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
    try:
        checks["redis"] = await redis_client.ping()
    except Exception:
        logger.exception("Redis health check failed")
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
            checks["database"] = True
    except Exception:
        logger.exception("Database health check failed")
    healthy = all(checks.values())
    payload = {"status": "ok" if healthy else "degraded", "checks": checks}
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
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ThreatEvent).order_by(desc(ThreatEvent.timestamp)).limit(limit)
    )
    return [serialize_event(event) for event in result.scalars()]


@app.get("/api/stats", dependencies=[Depends(require_dashboard_auth)])
async def get_stats(db: AsyncSession = Depends(get_db)):
    client = redis_client._require_client()
    cached = await client.get("dashboard:stats")
    if cached:
        return json.loads(cached)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    minute_ago = now - timedelta(minutes=1)

    total_result = await db.execute(select(func.count(ThreatEvent.id)))
    ips_result = await db.execute(select(func.count(func.distinct(ThreatEvent.source_ip))))
    critical_result = await db.execute(
        select(func.count(DdosAlert.id)).where(
            DdosAlert.severity == "critical", DdosAlert.status == "new"
        )
    )
    types_result = await db.execute(
        select(ThreatEvent.attack_type, func.count(ThreatEvent.id))
        .where(ThreatEvent.timestamp >= cutoff)
        .group_by(ThreatEvent.attack_type)
        .order_by(desc(func.count(ThreatEvent.id)))
        .limit(5)
    )
    hour_result = await db.execute(
        select(
            func.date_trunc("hour", ThreatEvent.timestamp).label("hour_bin"),
            func.count(ThreatEvent.id),
        )
        .where(ThreatEvent.timestamp >= cutoff)
        .group_by("hour_bin")
        .order_by("hour_bin")
    )
    recent_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(ThreatEvent.timestamp >= minute_ago)
    )

    counts: dict[datetime, int] = {}
    for hour, count in hour_result.all():
        if hour:
            normalized = hour.replace(tzinfo=hour.tzinfo or timezone.utc).astimezone(timezone.utc)
            counts[normalized] = count
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    hourly = []
    for offset in range(23, -1, -1):
        hour = current_hour - timedelta(hours=offset)
        hourly.append({"hour": hour.strftime("%H:00"), "count": counts.get(hour, 0)})

    payload = {
        "totalThreats": total_result.scalar() or 0,
        "attacksPerSecond": round((recent_result.scalar() or 0) / 60.0, 2),
        "criticalAlerts": critical_result.scalar() or 0,
        "uniqueIPs": ips_result.scalar() or 0,
        "topAttackTypes": [
            {"type": attack_type or "unknown", "count": count}
            for attack_type, count in types_result.all()
        ],
        "threatsByHour": hourly,
    }
    await client.setex("dashboard:stats", 5, json.dumps(payload))
    return payload


@app.get("/api/ml/status", dependencies=[Depends(require_dashboard_auth)])
async def ml_status(db: AsyncSession = Depends(get_db)):
    eligible_by_scope: dict[str, dict[str, int]] = {}
    for scope, minimum_requests in (
        ("server", settings.ML_MIN_SERVER_REQUESTS),
        ("source", settings.ML_MIN_SOURCE_REQUESTS),
    ):
        counts = await db.execute(
            select(TrafficWindow.server_id, func.count(TrafficWindow.id))
            .where(
                TrafficWindow.scope == scope,
                TrafficWindow.is_training_eligible.is_(True),
                TrafficWindow.rule_threat_count == 0,
                TrafficWindow.request_count >= minimum_requests,
            )
            .group_by(TrafficWindow.server_id)
        )
        eligible_by_scope[scope] = {
            server_id: count for server_id, count in counts.all()
        }
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


_analysis_status: dict[str, object] = {"state": "idle", "processed": 0, "total": 0}


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


async def _process_uploaded_lines(lines: list[str]) -> None:
    _analysis_status.update(state="running", processed=0, total=len(lines), error=None)
    try:
        for start in range(0, len(lines), 100):
            pending: list[PendingThreat] = []
            chunk = lines[start : start + 100]
            for line in chunk:
                log_entry = parse_event({"raw_log": line}, "manual-upload")
                if log_entry:
                    detected = await detection_engine.process_log(log_entry)
                    if detected:
                        pending.append(PendingThreat(detected))
            async with AsyncSessionLocal() as db:
                await persist_threats(db, pending)
            _analysis_status["processed"] = min(start + len(chunk), len(lines))
            await asyncio.sleep(0)
        _analysis_status["state"] = "complete"
    except Exception as exc:
        logger.exception("Uploaded log analysis failed")
        _analysis_status.update(state="error", error=str(exc))


@app.post("/api/analyze-log-file", dependencies=[Depends(require_dashboard_auth)])
async def analyze_log_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if _analysis_status.get("state") in {"queued", "running"}:
        raise HTTPException(409, "A log analysis is already running")
    content = await file.read(settings.MAX_LOG_SIZE_BYTES + 1)
    await file.close()
    if len(content) > settings.MAX_LOG_SIZE_BYTES:
        raise HTTPException(413, "Log file too large")
    lines = [line for line in content.decode("utf-8", errors="ignore").splitlines() if line.strip()]
    _analysis_status.update(state="queued", processed=0, total=len(lines), error=None)
    background_tasks.add_task(_process_uploaded_lines, lines)
    return {"status": "Analysis started", "lines": len(lines)}


@app.get("/api/analysis-status", dependencies=[Depends(require_dashboard_auth)])
async def analysis_status():
    return _analysis_status


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
                "port": 80,
                "type": threat.attack_type,
                "severity": threat.severity,
                "created_at": threat.timestamp.isoformat() if threat.timestamp else None,
            }
            for threat in threats
        ],
        "abuseData": abuse_data,
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
    if not settings.GROQ_API_KEY:
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
                    "model": "llama-3.3-70b-versatile",
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
