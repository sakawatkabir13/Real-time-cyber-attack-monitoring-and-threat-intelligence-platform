"""
Detection Engine — core threat classification pipeline.

Each log entry is run through:
  1. Redis event-time request and context counters
  2. AbuseIPDB reputation cache lookup
  3. Rule-based attack pattern matching (SQL injection, XSS, path traversal,
     scanner indicators, authentication failures, contextual HTTP-flood warnings)
  4. Real server/source traffic-window aggregation
Completed-window IsolationForest scoring runs independently in the scheduled worker.

Returns ThreatEventCreate for suspicious observations, or None for normal traffic.
Normal traffic is intentionally NOT saved to the database so that dashboard
counts reflect real threats rather than total analyzed requests.
"""

import re
import json
import logging
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit
import uuid

from app.config import settings
from app.schemas.ingest import LogEntry
from app.schemas.event import ThreatEventCreate
from app.services.behavioral_features import AUTH_PATH_RE, behavioral_features
from app.redis_client import redis_client
from app.services.log_parser import parse_timestamp

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
    r"wfuzz|nuclei|whatweb|shodan|zgrab|censys)",
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
_BRUTE_PATH_RE = AUTH_PATH_RE

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
        if log.event_id is None:
            log.event_id = uuid.uuid4().hex
        profile = settings.DETECTION_PROFILES.get(log.server_id, settings.DETECTION_DEFAULT_PROFILE)
        path = urlsplit(log.path or "/").path or "/"
        auth = bool(_BRUTE_PATH_RE.search(path))
        counts = await redis_client.event_counts(
            log.source_ip, server_id=log.server_id, timestamp=dt.timestamp(),
            event_id=log.event_id,
            counters={
                "requests": True, f"path:{path}": True,
                "server_errors": log.status_code >= 500,
                "timed": log.request_time is not None,
                "slow": log.request_time is not None and log.request_time >= profile.slow_request_seconds,
                "auth": auth, "failed_auth": auth and log.status_code in (401, 403),
            },
        )
        counts["same_path"] = counts[f"path:{path}"]

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
        rule_event = await self._detect_rule(log, dt, counts["requests"], counts)

        # ── Steps 4–5: Record every request into behavioral windows. ─────────
        # Known rule incidents are retained for visibility but excluded from
        # future baseline training. Only completed windows are scored.
        await behavioral_features.observe(
            log=log,
            timestamp=dt,
            rule_threat=rule_event is not None,
            reputation_score=float(ip_data.get("reputation_score", 0) or 0),
            reporter_count=int(ip_data.get("number_of_reporters", 0) or 0),
            community_reports=int(ip_data.get("community_reports", 0) or 0),
        )
        # Completed windows are scored independently of future requests.
        return rule_event

    async def _detect_rule(
        self, log: LogEntry, dt: datetime, request_volume: int,
        counts: dict[str, int] | None = None,
    ) -> ThreatEventCreate | None:
        path = log.path or ""
        ua = log.user_agent or ""
        status = log.status_code or 0
        counts = counts or {}
        profile = settings.DETECTION_PROFILES.get(log.server_id, settings.DETECTION_DEFAULT_PROFILE)

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
        failed_auth_attempts = counts.get("failed_auth", 0)
        failed_ratio = failed_auth_attempts / max(1, counts.get("auth", 0))
        if (is_auth_path and is_auth_failure
                and failed_auth_attempts > profile.failed_auth_threshold
                and failed_ratio >= profile.failed_auth_ratio):
            return self._make_event(
                log, dt,
                attack_type="brute_force",
                severity="high",
                anomaly_score=82.0,
                explanation=(
                    f"Possible brute force: {failed_auth_attempts} authentication failures "
                    f"({failed_ratio:.0%} of authentication requests) in five minutes of "
                    f"request time. Latest endpoint {path}, HTTP {status}. Investigate; "
                    "this does not establish account compromise."
                ),
            )

        # Count alone is not denial of service: require concentration AND
        # corroborating server errors or measured slow responses.
        concentration = counts.get("same_path", 0) / max(1, request_volume)
        errors = counts.get("server_errors", 0) / max(1, request_volume)
        slow = counts.get("slow", 0) / max(1, counts.get("timed", 0))
        timing_coverage = counts.get("timed", 0) / max(1, request_volume)
        if (request_volume > profile.request_threshold
                and concentration >= profile.path_concentration
                and (errors >= profile.server_error_ratio
                     or (timing_coverage >= 0.5 and slow >= profile.slow_request_ratio))):
            return self._make_event(
                log, dt, attack_type="http_flood", severity="high", anomaly_score=80.0,
                explanation=(f"Possible HTTP flood: {request_volume} requests in five minutes "
                             f"of request time, {concentration:.0%} to the current path, "
                             f"{errors:.0%} HTTP 5xx, {slow:.0%} slow among measured requests "
                             f"({timing_coverage:.0%} timing coverage). A service fault or "
                             "legitimate surge can also explain this; investigate."),
            )

        # Scanner / Recon — known tool user-agents or sensitive path probing
        if _SCANNER_UA_RE.search(ua) or _SCANNER_PATH_RE.search(path):
            return self._make_event(
                log, dt,
                attack_type="scanner",
                severity="medium",
                anomaly_score=75.0,
                explanation=(
                    f"Reconnaissance indicator (not proof of exploitation). "
                    + (f"User-agent: {ua[:80]}. " if _SCANNER_UA_RE.search(ua) else "")
                    + (f"Probed path: {path[:80]}." if _SCANNER_PATH_RE.search(path) else "")
                ),
            )

        return None

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        return parse_timestamp(value)

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
