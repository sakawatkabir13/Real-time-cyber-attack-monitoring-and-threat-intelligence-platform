import hashlib
import hmac
import time

from fastapi import HTTPException, Request, WebSocket, status

from app.config import settings


SESSION_COOKIE = "vanguard_session"


def _signature(expires_at: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        expires_at.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_session_token() -> str:
    expires_at = str(int(time.time()) + settings.SESSION_TTL_SECONDS)
    return f"{expires_at}.{_signature(expires_at)}"


def is_valid_session(token: str | None) -> bool:
    if not token or "." not in token:
        return False
    expires_at, signature = token.split(".", 1)
    if not expires_at.isdigit() or int(expires_at) <= int(time.time()):
        return False
    return hmac.compare_digest(signature, _signature(expires_at))


def verify_dashboard_password(password: str) -> bool:
    return hmac.compare_digest(password, settings.DASHBOARD_PASSWORD)


def verify_collector_token(authorization: str | None) -> None:
    configured = settings.COLLECTOR_TOKEN
    if not configured or configured.startswith("change_me"):
        raise HTTPException(503, "Collector authentication is not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Expected Authorization: Bearer <token>")
    if not hmac.compare_digest(authorization[7:].strip(), configured):
        raise HTTPException(403, "Invalid collector token")


def client_identifier(request: Request) -> str:
    forwarded = request.headers.get("x-real-ip")
    if forwarded:
        return forwarded.strip()
    return request.client.host if request.client else "unknown"


async def require_dashboard_auth(request: Request) -> None:
    if not is_valid_session(request.cookies.get(SESSION_COOKIE)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )


def websocket_is_authenticated(websocket: WebSocket) -> bool:
    return is_valid_session(websocket.cookies.get(SESSION_COOKIE))
