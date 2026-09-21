# Detection improvements: measurements, completed windows, reviews, grouping

Implements recommendations **1–5 and 7**. Recommendation **6 is excluded**:
`backend/evaluate_model.py`, independent accuracy experiments, and the existing
training/validation methodology have not been redesigned. Functional tests do
not establish precision, recall, or a false-positive rate.

## What changed

1. **Measurements:** rules now count request timestamps, not batch arrival times.
   Authentication/API security rate limits still intentionally use wall-clock
   time. Counters are scoped by server and source, and collector event IDs prevent
   retries from incrementing them again. Adjacent timestamp buckets handle
   out-of-order records without counting future records backward. Historical and
   current traffic never share a time bucket. Counter buckets survive one hour
   after receiving a record by default (`EVENT_COUNTER_TTL_SECONDS`); later
   deliveries beyond that retention can undercount earlier traffic. Rules cannot
   retroactively detect every sequence missed before an out-of-order record arrived.
   Missing, invalid, timezone-less, and far-future timestamps are rejected rather
   than replaced with arrival time. Upload status reports rejected lines.

   Unknown response duration is stored as NULL, not zero. Measured durations use
   seconds. Window averages include only measured requests and carry a separate
   measurement-coverage feature. The model's numeric missing-value placeholder
   is accompanied by this coverage feature, so missing timing is distinguishable
   from measured zero-second responses.

2. **Completed-window scoring:** the API starts a periodic background worker
   (every 10 seconds by default) backed by a Redis due queue and per-window locks.
   It does not depend on another request arriving. Scoring waits for window end
   plus a grace period, and for a quiet grace period after late/replayed records.
   Model warm-up and transient failures leave work queued. Windows remain in
   Redis for eight days; work older than this expires with its window. This is
   bounded operational retention, not an unlimited historical scoring service.

   ML events carry the completed window's timestamp and source. Server-wide
   anomalies have no single source IP and no invented map coordinates. Late data
   requeues affected windows (including the following window's rate-change
   context). Each ML window has its own reviewable alert; rule alerts retain
   their time-bucket deduplication. Revisions update the same finding without incrementing the alert's
   occurrence count. If a revision no longer qualifies, the earlier finding is
   retained at low severity with an explanation, not silently deleted. Human
   verdicts are preserved. `GET /api/ml/status` exposes the scorer heartbeat.

3. **Contextual rules:** ordinary curl, wget, Python requests, and Go clients are
   not scanner evidence by themselves. A high request count alone no longer
   creates a critical `ddos` finding or excludes busy normal traffic from training.
   The new `http_flood` warning requires more than 100 requests in five minutes,
   at least 80% to the current path, plus either at least 50% server errors or
   at least 50% slow measured responses (at least half the requests must have
   timing). Slow means three seconds by default. These are configurable evidence
   thresholds, not proven universal attack boundaries. A service fault can also
   explain the warning. Brute-force warnings require more than 15 authentication
   failures and an authentication-failure ratio of at least 80%.

   Override a server using `DETECTION_PROFILES`, for example:

   ```dotenv
   DETECTION_PROFILES={"spandan-web":{"request_threshold":300,"failed_auth_threshold":20}}
   ```

   Use the actual collector `SERVER_ID`. Existing historical `ddos` records are
   retained. This remains HTTP log-based detection, not packet-level protection
   or automatic request blocking.

4. **Behavioral features:** peak requests per second, busiest-second share,
   change from the preceding window, preceding-window availability,
   authentication-failure ratio, timing coverage, source-level path concentration,
   and server-level distinct sources targeting a path. Existing rates, status
   ratios, diversity, and time-of-day features remain. Individual path tracking
   is capped at 128 paths per window; overall diversity uses HyperLogLog. Thus
   the same-path source count is an approximate, bounded observation—not a
   complete coordinated-attacker inventory.

5. **Investigation:** Alerts now support confirmed malicious, legitimate,
   misconfiguration, and uncertain verdicts with required notes. Every saved
   review has an append-only revision record. Concurrent edits get HTTP 409
   instead of overwriting another review. ACK remains separate. The current
   shared dashboard login identifies the reviewer as `dashboard_operator`, not
   a verified individual person. Reviews do not automatically change training
   data or become evaluation ground truth.

7. **Related incidents:** a background DBSCAN pass groups bounded recent source
   alerts with matching server, detection family and normalized path, nearby
   timing/scores, and—when available—similar persisted source-window ratios.
   At least three distinct sources are required by default. Legitimate and
   misconfiguration verdicts are excluded on the next pass. Groups appear on
   the Alerts page and preserve individual alerts and reviews. DBSCAN proximity
   can chain through neighboring observations; a group is a suggested
   investigation aid, never attribution to one attacker. Default limits: latest
   500 source alerts in an hour, every 60 seconds. Source lists show at most 50 IPs.

## Configure real response times on the monitored site

The existing collector already forwards JSON lines. No new collector protocol
or collector reinstall is needed. Configure only the monitored site's own log;
do not collect Vanguard's ingestion traffic or another application's log.

For host Nginx, define this format inside the existing `http { ... }` context:

```nginx
log_format vanguard_json escape=json
  '{"timestamp":$msec,"source_ip":"$remote_addr",'
  '"method":"$request_method","path":"$request_uri",'
  '"status_code":$status,"bytes_sent":$body_bytes_sent,'
  '"request_time":$request_time,"user_agent":"$http_user_agent",'
  '"host":"$host"}';
```

Select it in Spandan's existing HTTPS server block:

```nginx
access_log /var/log/nginx/spandan.access.log vanguard_json;
```

Check location-specific logging overrides. Keep the collector `LOG_PATH` aligned,
and retain existing trusted-proxy/client-IP configuration. Validate and reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Combined logs remain supported without timing. Alternatively append
`rt=$request_time` to a standard Nginx combined format. For Apache, append
`rt_us=%D` to its standard combined `LogFormat`; the parser converts microseconds
to seconds. Structured JSON may also supply `request_time_us`. Do not configure
an arbitrary bare numeric duration without specifying its unit.

Nginx access-log timestamps describe the logged request's completion time. These
features are limited by the timing and coverage available in the log; they do
not measure SYN floods, dropped packets, or traffic blocked before the origin.

## Existing installations: migration and model transition

This is a code change, not an automatic VPS deployment. Back up PostgreSQL and
the model artifact before upgrading. Run from the correct Vanguard Compose
directory and use its existing environment file. Do not delete volumes.

1. Build the updated backend/worker and frontend images through your existing
   deployment workflow. Pause Vanguard's backend, worker, and beat during the
   migration so old and new code do not write different feature schemas.
2. Apply `alembic upgrade head` with the new backend image. Revision
   `0003_detection_context` adds columns/tables and makes server-wide event IPs
   nullable. Existing event/alert/window history is preserved. There is no
   destructive downgrade; rollback requires your pre-upgrade backup.
3. Start the updated backend, Celery worker/beat, and frontend. Keep the Compose
   backend at **one Uvicorn worker**: live WebSocket connections still reside in
   that API process. The new API background workers handle scoring/grouping;
   Celery continues window persistence and training. Ensure your proxy reaches
   the recreated containers through your existing deployment procedure.
4. Supply real request durations using the log configuration above.
5. Check `/api/health`, Settings → ML status, scorer logs/heartbeat, and Alerts.

Models now use **feature schema 3**. Schema-2 artifacts cannot safely score the
new inputs and are not loaded. Existing database windows remain intact but are
not relabeled as schema 3. The usual scheduled training must accumulate enough
new, eligible windows per server/scope (200 by default) before ML becomes ready.
Rules continue working during warm-up. The existing training/validation algorithm
is unchanged; only schema eligibility and artifact compatibility were updated.

Example migration command after building and pausing the affected services:

```bash
docker compose run --rm --no-deps -e RUN_MIGRATIONS=0 backend alembic upgrade head
docker compose up -d backend celery_worker celery_beat frontend
```

## Regression tests

```bash
cd backend
python -m pytest
```

The opt-in PostgreSQL workflow test requires a migrated disposable database named
`vanguard_test*`, supplied through `VANGUARD_TEST_DATABASE_URL`. It writes uniquely
named test records and stubs model predictions/geolocation. Never use a live DB.

```bash
cd frontend
npm test
npm run build
```

The old classroom exercise of 110 lightweight HTTP 200 responses is now a useful
negative control: **count alone should not trigger an HTTP-flood rule warning**.
Do not claim this change improves measured model accuracy; point 6 remains future work.
