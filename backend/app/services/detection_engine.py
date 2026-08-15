"""
Detection Engine — core threat classification pipeline.

Each log entry is run through:
  1. Redis sliding-window request volume counter
  2. AbuseIPDB reputation cache lookup
  3. Rule-based attack pattern matching (SQL injection, XSS, path traversal,
     scanner detection, brute-force detection, DDoS volume threshold)
  4. Real server/source traffic-window aggregation
  5. Behavioral IsolationForest scoring of completed clean windows

Returns ThreatEventCreate for actual threats, or None for normal traffic.
Normal traffic is intentionally NOT saved to the database so that dashboard
counts reflect real threats rather than total analyzed requests.
"""

import re
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from app.schemas.ingest import LogEntry
from app.schemas.event import ThreatEventCreate
from app.services.behavioral_features import behavioral_features
from app.redis_client import redis_client

logger = logging.getLogger(__name__)


# ── Attack signature patterns ──────────────────────────────────────────────────

# SQL Injection — matches common SQL keywords and syntax in URL paths/params
_SQL_RE = re.compile(
    r"(union[\s\+]+(?:all[\s\+]+)?select|select.{0,20}from|insert[\s\+]+into|"
    r"update.{0,20}set[\s\+]|delete[\s\+]+from|drop[\s\+]+(?:table|database)|"
    r"exec(?:ute)?[\s\+(]|xp_\w+|benchmark[\s\+(]|sleep[\s\+(]|"
    r"waitfor[\s\+]+delay|'\s*(?:or|and)\s*'|--\s|;\s*(?:drop|select|insert)|"
    r"/\*.*?\*/|0x[0-9a-f]{4,})",
    re.IGNORECASE,
)

# Cross-Site Scripting — script tags, event handlers, dangerous JS calls
_XSS_RE = re.compile(
    r"(<\s*script[\s>]|</\s*script|javascript\s*:|"
    r"on(?:load|click|error|mouseover|focus|blur|input|submit)\s*=|"
    r"<\s*iframe[\s>]|<\s*img[^>]+onerror\s*=|"
    r"eval\s*\(|document\.cookie|document\.write|alert\s*\(|"
    r"String\.fromCharCode|&#\d+;|%3cscript)",
    re.IGNORECASE,
)

# Path Traversal — directory escape sequences and sensitive file targets
_TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.\\|%2e%2e(?:%2f|%5c)|%252e%252e|"
    r"/etc/(?:passwd|shadow|hosts|crontab)|"
    r"/proc/self/|/var/log/|/root/\.ssh|"
    r"(?:win(?:dows)?[\\/])?system32[\\/]|boot\.ini|win\.ini)",
    re.IGNORECASE,
)

# Scanner / Recon tool user-agents — common pentest and automated scanners
_SCANNER_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|metasploit|nessus|openvas|"
    r"w3af|acunetix|ibm\s*appscan|dirbuster|gobuster|ffuf|"
    r"wfuzz|nuclei|whatweb|shodan|zgrab|censys|"
    r"python-requests/[0-9]|go-http-client/[0-9]|"
    r"libwww-perl|scrapy|mechanize|curl/[0-9]|wget/[0-9])",
    re.IGNORECASE,
)

# Scanner / Recon target paths — sensitive files commonly probed by scanners
_SCANNER_PATH_RE = re.compile(
    r"(\.env$|\.git/config|\.htaccess|\.htpasswd|web\.config|"
    r"phpinfo\.php|php-info\.php|info\.php|"
    r"wp-admin|wp-login\.php|wp-config\.php|xmlrpc\.php|"
    r"phpmyadmin|/pma/|/admin/|/manager/html|"
    r"/shell\.|/cmd\.|/backdoor\.|/c99\.|/r57\.|"
    r"\.(bak|old|backup|sql|dump|tar\.gz|zip)(?:\?|$))",
    re.IGNORECASE,
)

# Brute Force target paths — authentication endpoints
_BRUTE_PATH_RE = re.compile(
    r"(/(?:api/)?(?:login|signin|auth|token|session)|"
    r"/user/login|/account/(?:login|signin)|"
    r"/wp-login\.php|/admin/login|/panel/login)",
    re.IGNORECASE,
)

# ── Thresholds ─────────────────────────────────────────────────────────────────

DDOS_THRESHOLD = 100          # requests in 5-min window → DDoS
BRUTE_FORCE_THRESHOLD = 15    # requests on auth path with 401/403 → Brute Force
# ── Main engine ────────────────────────────────────────────────────────────────

class DetectionEngine:

    async def process_log(self, log: LogEntry) -> Optional[ThreatEventCreate]:
        """
        Process a single log entry through the full detection pipeline.

        Returns ThreatEventCreate if a threat is detected, or None for normal traffic.
        Returning None for normal traffic keeps the database and dashboard counts
        accurate — only real threats are persisted.
        """
        dt = self._parse_timestamp(log.timestamp)

        # ── Step 1: Request volume (sliding 5-minute window per IP) ───────────
        request_volume = await redis_client.increment_window(
            log.source_ip,
            window_size=300,
            server_id=log.server_id,
            scope="requests",
        )

        # ── Step 2: IP reputation from Redis (populated by enrich_ip_task) ───
        client = redis_client._require_client()
        ip_data_str = await client.get(f"ip_data:{log.source_ip}")
        if ip_data_str:
            try:
                ip_data = json.loads(ip_data_str)
            except (TypeError, ValueError):
                ip_data = {}
        else:
            # Queue background AbuseIPDB fetch for next time this IP appears
            try:
                from app.tasks.enrich_ips import enrich_ip_task
                enrich_ip_task.delay(log.source_ip)
            except Exception:
                pass
            ip_data = {"reputation_score": 0, "number_of_reporters": 0, "community_reports": 0}
        if not isinstance(ip_data, dict):
            ip_data = {}

        # ── Step 3: Rule-based classification ────────────────────────────────
        rule_event = await self._detect_rule(log, dt, request_volume)

        # ── Steps 4–5: Record every request into behavioral windows. ─────────
        # Known rule incidents are retained for visibility but excluded from
        # future baseline training. Only completed windows are scored.
        finding = await behavioral_features.observe(
            log=log,
            timestamp=dt,
            rule_threat=rule_event is not None,
            reputation_score=float(ip_data.get("reputation_score", 0) or 0),
            reporter_count=int(ip_data.get("number_of_reporters", 0) or 0),
            community_reports=int(ip_data.get("community_reports", 0) or 0),
        )
        if rule_event is not None:
            return rule_event
        if finding is not None:
            return self._make_event(
                log,
                dt,
                attack_type=finding.attack_type,
                severity=finding.severity,
                anomaly_score=finding.score,
                explanation=finding.explanation,
            )
        return None

    async def _detect_rule(
        self, log: LogEntry, dt: datetime, request_volume: int
    ) -> ThreatEventCreate | None:
        path = log.path or ""
        ua = log.user_agent or ""
        status = log.status_code or 0

        # DDoS — very high request volume from single IP
        if request_volume > DDOS_THRESHOLD:
            return self._make_event(
                log, dt,
                attack_type="ddos",
                severity="critical",
                anomaly_score=95.0,
                explanation=(
                    f"DDoS detected: {int(request_volume)} requests from "
                    f"{log.source_ip} in the last 5 minutes (threshold: {DDOS_THRESHOLD})."
                ),
            )

        # SQL Injection — SQL syntax in URL path or query string
        if _SQL_RE.search(path):
            return self._make_event(
                log, dt,
                attack_type="sql_injection",
                severity="high",
                anomaly_score=90.0,
                explanation=(
                    f"SQL injection pattern detected in request path: {path[:120]}"
                ),
            )

        # XSS — script injection in URL
        if _XSS_RE.search(path):
            return self._make_event(
                log, dt,
                attack_type="xss",
                severity="high",
                anomaly_score=85.0,
                explanation=(
                    f"Cross-site scripting (XSS) pattern detected in path: {path[:120]}"
                ),
            )

        # Path Traversal — directory escape or sensitive file access
        if _TRAVERSAL_RE.search(path):
            return self._make_event(
                log, dt,
                attack_type="path_traversal",
                severity="high",
                anomaly_score=88.0,
                explanation=(
                    f"Path traversal attempt detected: {path[:120]}"
                ),
            )

        # Brute Force — repeated auth failures from same IP
        is_auth_path = bool(_BRUTE_PATH_RE.search(path))
        is_auth_failure = status in (401, 403)
        failed_auth_attempts = 0
        if is_auth_path and is_auth_failure:
            failed_auth_attempts = await redis_client.increment_window(
                log.source_ip,
                window_size=300,
                server_id=log.server_id,
                scope="failed_auth",
            )
        if failed_auth_attempts > BRUTE_FORCE_THRESHOLD:
            return self._make_event(
                log, dt,
                attack_type="brute_force",
                severity="high",
                anomaly_score=82.0,
                explanation=(
                    f"Brute force detected: {failed_auth_attempts} failed requests to "
                    f"auth endpoint {path} with HTTP {status} responses."
                ),
            )

        # Scanner / Recon — known tool user-agents or sensitive path probing
        if _SCANNER_UA_RE.search(ua) or _SCANNER_PATH_RE.search(path):
            return self._make_event(
                log, dt,
                attack_type="scanner",
                severity="medium",
                anomaly_score=75.0,
                explanation=(
                    f"Automated scanner detected. "
                    + (f"User-agent: {ua[:80]}. " if _SCANNER_UA_RE.search(ua) else "")
                    + (f"Probed path: {path[:80]}." if _SCANNER_PATH_RE.search(path) else "")
                ),
            )

        return None

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        if value:
            try:
                parsed = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
                return parsed.astimezone(timezone.utc)
            except ValueError:
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    return parsed.astimezone(timezone.utc)
                except ValueError:
                    logger.debug("Invalid log timestamp %r; using current time", value)
        return datetime.now(timezone.utc)

    @staticmethod
    def _make_event(
        log: LogEntry,
        dt: datetime,
        attack_type: str,
        severity: str,
        anomaly_score: float,
        explanation: str,
    ) -> ThreatEventCreate:
        return ThreatEventCreate(
            server_id=log.server_id,
            timestamp=dt,
            source_ip=log.source_ip,
            method=log.method,
            path=log.path,
            status_code=log.status_code,
            bytes_sent=log.bytes_sent,
            request_time=log.request_time,
            user_agent=log.user_agent,
            host=log.host,
            attack_type=attack_type,
            severity=severity,
            anomaly_score=anomaly_score,
            explanation=explanation,
        )


detection_engine = DetectionEngine()
