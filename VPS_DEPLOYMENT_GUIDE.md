# Vanguard-360 production VPS deployment

This guide uses Docker Compose for Vanguard-360 and host-level Nginx/Certbot for TLS. Examples assume Ubuntu 24.04 and `vanguard.example.com` points to the VPS.

## 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2 nginx certbot python3-certbot-nginx git
sudo systemctl enable --now docker nginx
sudo usermod -aG docker "$USER"
```

Log out and back in after changing Docker group membership.

## 2. Configure and start Vanguard-360

```bash
sudo install -d -o "$USER" -g "$USER" /opt/vanguard-360
git clone YOUR_REPOSITORY_URL /opt/vanguard-360
cd /opt/vanguard-360
cp .env.example .env
nano .env
```

Set at least:

```dotenv
ENVIRONMENT=production
POSTGRES_PASSWORD=a-long-random-database-password
DATABASE_URL=postgresql+asyncpg://vanguard:THE_SAME_PASSWORD@postgres:5432/vanguardmap
DATABASE_SSL=false
COLLECTOR_TOKEN=a-separate-long-random-agent-token
SECRET_KEY=a-long-random-cookie-signing-key
DASHBOARD_PASSWORD=a-strong-dashboard-password
BIND_ADDRESS=127.0.0.1
HTTP_PORT=8080
COOKIE_SECURE=true
CORS_ORIGINS=[]
```

Generate independent values with `openssl rand -hex 32`. Do not reuse the dashboard password as a collector or signing secret. Optional AbuseIPDB, Groq, and MaxMind values may remain blank.

Keep `CORS_ORIGINS=[]` for this deployment. The browser loads the dashboard and accesses `/api` and `/ws` through the same `https://vanguard.example.com` origin, so CORS permission is not required. Only add an exact origin when the frontend is deliberately hosted on a different scheme, hostname, or port. Never use `*` with credentialed session cookies.

Protect the environment file and start the stack:

```bash
chmod 600 .env
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:8080/api/health
```

The backend applies Alembic migrations before Uvicorn starts. Keep the supplied `--workers 1`: live WebSocket connections are process-local. Multiple API workers require Redis pub/sub or another shared broadcaster first.

## 3. Add HTTPS

Create `/etc/nginx/sites-available/vanguard-360`:

```nginx
server {
    listen 80;
    server_name vanguard.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
```

Enable the site and request a certificate:

```bash
sudo ln -s /etc/nginx/sites-available/vanguard-360 /etc/nginx/sites-enabled/vanguard-360
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d vanguard.example.com
```

Allow only SSH and web traffic in the VPS firewall/security group. PostgreSQL, Redis, the API, and the frontend have no direct host port mappings.

## 4. Install collectors

On each monitored web server, copy this repository's `agent/` directory:

```bash
cd agent
cp .env.example .env
nano .env
sudo ./install.sh
```

Example:

```dotenv
BACKEND_URL=https://vanguard.example.com
COLLECTOR_TOKEN=the-exact-backend-collector-token
LOG_PATH=/var/log/nginx/access.log
SERVER_ID=web-01
SPOOL_PATH=/var/lib/vanguard-agent/spool.db
START_AT_END=true
BATCH_SIZE=100
FLUSH_INTERVAL=5
MAX_SPOOL_EVENTS=100000
HEARTBEAT_INTERVAL=10
```

Every server needs a stable, unique `SERVER_ID`; behavioral baselines and dashboard commands are scoped by it. Verify delivery:

```bash
sudo systemctl status vanguard-agent
sudo journalctl -u vanguard-agent -f
```

Successful sends log `Delivered N log events`. Network failures stay in SQLite and retry automatically. Dashboard Pause stops forwarding but continues spooling; Resume drains the queue. The dashboard cannot start a systemd service that is offline.

## 5. ML warm-up and monitoring

The system aggregates real traffic immediately, persists completed windows every minute, and attempts per-server model training daily at 03:30 UTC. It never falls back to synthetic training data. With the defaults, each scope needs 200 eligible windows for a server; low-volume servers can therefore take time to warm up.

Review Settings for model version, active sample count, and window progress. To run maintenance immediately:

```bash
docker compose exec celery_worker python -c \
  "from app.tasks.flush_traffic_windows import flush_traffic_windows_task; print(flush_traffic_windows_task.run())"
docker compose exec celery_worker python -c \
  "from app.tasks.train_model import train_model_task; print(train_model_task.run())"
docker compose exec backend python evaluate_model.py --days 7
```

Do not reduce `ML_MIN_TRAINING_WINDOWS` merely to force a production model. First confirm there is enough representative traffic across normal busy/quiet periods. A model can be operationally ready while a newly added server remains in per-server warm-up.

## 6. Back up, upgrade, and recover

Back up PostgreSQL before upgrades:

```bash
cd /opt/vanguard-360
docker compose exec -T postgres pg_dump -U vanguard vanguardmap > vanguard-backup.sql
git pull --ff-only
docker compose up -d --build
docker compose ps
curl https://vanguard.example.com/api/health
```

The model volume is reproducible from retained traffic windows, but you can additionally back it up if immediate ML continuity matters. Useful diagnostics:

```bash
docker compose logs --tail=200 backend
docker compose logs --tail=200 celery_worker celery_beat
docker compose exec backend alembic current
docker compose exec redis redis-cli ping
docker compose exec backend ls -lh /models
```

Use `docker compose down` to stop without deleting data. Do not add `-v` unless you intentionally want to permanently delete PostgreSQL, Redis, model, and scheduler volumes.
