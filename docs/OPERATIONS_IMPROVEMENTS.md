# Operations and independent evaluation

## Independently evaluate detection

The old `backend/evaluate_model.py` compared ML with rule matches and could not
establish accuracy. It has been removed. The replacement requires labels obtained
from a controlled test or a human investigation, independently of both detectors.

After a model exists and later traffic windows have been saved:

```bash
cd backend
python evaluate_independent.py export /tmp/vanguard-candidates.jsonl --days 7
```

Each JSONL row contains its model features and observed `rule_detected` result.
Review each row and set `label` to `attack` or `benign` based on independent
evidence. For an attack, optionally add its verified `attack_start`, and actual
`rule_alert_at`/`ml_alert_at` timestamps from the controlled run or alert
records. Do not invent timestamps; missing timing stays missing. Do not label a
window as an attack merely because a rule or model flagged it. Keep the reviewed
dataset private: features and server IDs can reveal traffic patterns.

```bash
python evaluate_independent.py evaluate /path/to/reviewed.jsonl \
  --period-start 2026-10-01T00:00:00Z \
  --period-end 2026-10-08T00:00:00Z
```

The declared period must cover observation time, including quiet intervals. The
tool refuses unlabeled rows, missing model scopes, and windows on or before their
model's training end. It reports precision, recall, false-positive rate, benign
windows flagged per day, and measured detection delay where timestamps exist for
rules alone, ML alone, and their union. Metrics are per window, not unique attack
incidents. A replayed model score is not a measured alert timestamp. No accuracy
claim is justified until a real, independently labeled holdout exists.

## External health checks and email

GitHub Actions runs `.github/workflows/monitor.yml` from outside the VPS every
five minutes once the repository variable `VANGUARD_MONITOR_ENABLED` is `true`.
A manual run is available in Actions. It checks the public health endpoint,
PostgreSQL, Redis, scorer, incident grouper, Celery path, collector, WebSocket
relay, disk usage (default alert at 90%), and model freshness once trained.
Model warm-up is not treated as a failure. The first failure creates a GitHub
issue and emails the operator; recovery closes the issue and emails again.
Ongoing failures update the same issue rather than sending a message every five
minutes. GitHub's scheduled runner can be delayed; this is not a hard real-time
alarm.

The sender is `community.cuetinsights@gmail.com` and the recipient is
`sakawatkabir13@gmail.com`. Create a Google app password for the sender account
and store it only as the repository secret `MONITOR_SMTP_APP_PASSWORD`. Enable
two-step verification if Google requires it. Never commit or paste the password.
The monitor uses `smtp.gmail.com:587` with STARTTLS. Enable the repository
variable only after testing a manual run. Missing SMTP credentials leave a
GitHub issue/workflow failure but cannot send email.

The API's `/api/health` keeps PostgreSQL and Redis as HTTP 503 dependencies.
Background signals are diagnostic fields because they can start later than the
API. The external monitor treats stale background signals as failures. The
WebSocket Redis relay now retries with bounded backoff and reports a heartbeat
even if no threat events arrive.

## Optional local MaxMind GeoLite2 database

No MaxMind account/license is currently configured, so the existing GeoJS
fallback remains active. When ready, create a MaxMind account with access to
`GeoLite2-City`, then create these two private files on the VPS:

```text
/var/www/vanguard-360/secrets/maxmind_account_id.txt
/var/www/vanguard-360/secrets/maxmind_license_key.txt
```

The files are gitignored; keep directory mode 700 and file mode 600. Put only
the corresponding credential in each file, without extra quoting. In the VPS
`.env`, set `MAXMIND_DB_PATH=/geoip/GeoLite2-City.mmdb`. From the deployed
Compose directory:

```bash
docker compose --profile geoip up -d geoipupdate
docker compose logs --tail=50 geoipupdate
docker compose restart backend celery_worker
```

The optional updater checks every 72 hours. Backend and worker read the shared
database volume; the lookup service hot-reloads the database after replacement.
If the file is unavailable, lookups still use GeoJS. Verify the database exists
in the updater volume before claiming the local path is active. Do not enable the
profile with empty credentials. MaxMind's updater setup follows its
[official Docker guide](https://github.com/maxmind/geoipupdate/blob/main/doc/docker.md).

## CI and manual deployment

`.github/workflows/ci.yml` runs backend/agent tests, the full PostgreSQL
integration test against a disposable migrated `vanguard_test_ci` database,
frontend tests/lint/build, dependency audits, image builds, Compose validation,
and secret scanning. The integration test must never point to production.
Dependency audits intentionally fail when they find unresolved advisories.

`.github/workflows/deploy.yml` is manual only, requires all CI jobs to pass,
and targets the `production` GitHub environment. Configure required reviewers
on that environment before using it. Supply repository secrets
`VPS_HOST`, `VPS_SSH_PRIVATE_KEY`, and `VPS_SSH_KNOWN_HOSTS`; obtain and verify
the host key fingerprint independently before saving known_hosts. The workflow
accepts only the current main commit, refuses content-dirty VPS checkouts,
backs up PostgreSQL and any present model under the ignored `backups/`
directory, builds, migrates, restarts, and checks the public endpoint.
A failed migration needs operator intervention; this is not automatic rollback.

The former VPS-only `agent/install.sh` difference was just file mode 100644
versus 100755. It is tracked as executable in this change, matching the VPS;
there was no uncommitted installer code to merge.
