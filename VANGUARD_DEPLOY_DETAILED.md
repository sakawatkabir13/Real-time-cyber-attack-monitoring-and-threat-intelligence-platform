# Vanguard-360 — Detailed Deployment Guide
### Deploying alongside Spandan, CinemaSeat, and your portfolio on the same EC2

---

## Why No Override File This Time

Every previous app you deployed (Spandan, CinemaSeat, earlier Vanguard versions)
hardcoded container ports directly inside `docker-compose.yml`:

```yaml
ports:
  - "8000:8000"    # fixed, can't change without a separate override file
```

This forced you to create `docker-compose.override.yml` every time, just to
remap around whatever was already taken.

This version of Vanguard-360 was built differently. Only **one** service in
the whole stack exposes a port at all — the bundled `nginx` container, which
sits in front of the frontend and backend and proxies everything internally.
And that one port is read from your `.env` file natively:

```yaml
# inside the base docker-compose.yml — already parameterized
ports:
  - "${BIND_ADDRESS}:${HTTP_PORT}:80"
```

Change `BIND_ADDRESS`/`HTTP_PORT` in `.env`, the port changes. No second
compose file, no override layer, no port juggling. This is the simplest
deployment of any app you've done on this server so far.

---

## Your Current EC2 State (confirmed by the commands you ran)

```
Port 80/443    → Host Nginx (already serving Spandan, CinemaSeat, portfolio)
Port 8000      → Spandan backend
Port 8002      → CinemaSeat api (127.0.0.1 only)
Port 3000/3001 → CinemaSeat web
Port 9000      → CinemaSeat gateway (127.0.0.1 only)
Port 5432      → Spandan's Postgres (exposed — pre-existing, unrelated to this deploy)
Port 8080      → FREE — this is what Vanguard will use
```

Domain: `vanguard.cuetinsights.dev` — DNS presumably already pointed at this
EC2 (same pattern as your other `*.cuetinsights.dev` subdomains). Verify:

```bash
dig vanguard.cuetinsights.dev
```
Should return this EC2's public IP. If it doesn't yet, add the A record in
your DNS provider before continuing — everything from Step 5 onward needs
this to resolve correctly.

---

## Step 1 — Clone the Repository

```bash
cd /var/www
sudo git clone <your-repo-url> vanguard-360
sudo chown -R $USER:$USER vanguard-360
cd vanguard-360
```

Same pattern as Spandan and CinemaSeat — `/var/www/<app-name>` is where
every app on this server lives.

---

## Step 2 — Configure `.env`

```bash
cp .env.example .env
nano .env
```

Go through every value:

```env
# ── PostgreSQL ──────────────────────────────────────────────────────────
# This app gets its OWN Postgres container — completely separate from
# Spandan's or CinemaSeat's databases. No shared state, no risk of
# touching their data.
POSTGRES_DB=vanguardmap
POSTGRES_USER=vanguard
POSTGRES_PASSWORD=<generate below>

DATABASE_URL=postgresql+asyncpg://vanguard:<same_password>@postgres:5432/vanguardmap
# "postgres" here is the Docker service name inside THIS app's compose
# file — not related to Spandan's postgres container at all, even though
# both are named "postgres" internally. Docker keeps them isolated because
# each app runs in its own Compose "project" (see COMPOSE_PROJECT_NAME below).

# ── Redis ───────────────────────────────────────────────────────────────
REDIS_URL=redis://redis:6379/0

# ── Security ────────────────────────────────────────────────────────────
ENVIRONMENT=production
# In production mode, the app refuses to start if any secret below is
# still a placeholder value — a safety net against forgetting to change one.

COLLECTOR_TOKEN=<generate below>
SECRET_KEY=<generate below>
DASHBOARD_PASSWORD=<a real password, 12+ characters>

COOKIE_SECURE=true
# Already true by default in this version — keep it. Ensures the login
# session cookie is never sent over plain HTTP.

CORS_ORIGINS=[]
# Leave this empty. Unlike Spandan/CinemaSeat where frontend and API were
# separate ports needing CORS rules, here the bundled nginx makes frontend
# and API genuinely same-origin — the browser never needs cross-origin
# permission because it's always talking to the same domain/port.

# ── Networking — the ONE port this app uses ────────────────────────────
BIND_ADDRESS=127.0.0.1
HTTP_PORT=8080
# 127.0.0.1 means only Nginx on THIS machine can reach it — never exposed
# to the internet directly. Host Nginx is the only thing allowed to talk
# to it, same security pattern as CinemaSeat's api/gateway containers.

# ── Map coordinates — your server's physical location ──────────────────
TARGET_LATITUDE=23.8103
TARGET_LONGITUDE=90.4125
# Bangladesh/Dhaka coordinates — attack arcs on the live map point here.
# Change if your server is physically located elsewhere.

# ── Threat intelligence (optional but recommended) ─────────────────────
ABUSEIPDB_API_KEY=
# Free account at abuseipdb.com — enables IP reputation scoring.
# Leave blank and the app still works, just without reputation data.

GROQ_API_KEY=
# Free account at console.groq.com — enables the "AI Analysis" feature
# that explains threats in plain English. Optional.
```

Generate your three secrets — run this three separate times, paste each
result into the matching line above:

```bash
openssl rand -hex 32
```

Isolate this app's Docker containers from Spandan/CinemaSeat by name:

```bash
echo "COMPOSE_PROJECT_NAME=vanguard" >> .env
```

This is read automatically by `docker compose` — it's why you didn't need
to type `-p vanguard` on every command. Every container this app creates
gets a `vanguard_` or `vanguard-` prefix, so `docker ps` output for all
four apps stays easy to tell apart.

---

## Step 3 — Build and Start

```bash
docker compose up -d --build
```

What happens during this command, in order:
1. Postgres and Redis containers start first (other services wait for them)
2. Backend image builds — installs Python dependencies
3. Frontend image builds — installs Node dependencies, runs `npm run build`
4. Nginx image builds — bundles the compiled frontend + a reverse-proxy config
5. Backend's entrypoint script runs `alembic upgrade head` automatically —
   creates every database table before the API starts accepting requests
6. Celery worker and beat scheduler start — background jobs begin running

Watch it happen:
```bash
docker compose logs -f backend
```
Look for two lines in this order:
```
Applying database migrations...
Application startup complete.
```

Confirm everything is up:
```bash
docker compose ps
```
Every service should show `running` or `healthy`.

---

## Step 4 — Verify Locally (before touching Nginx)

```bash
curl http://127.0.0.1:8080/api/health
```
Expected:
```json
{"status": "ok", "checks": {"redis": true, "database": true}}
```

If this fails, stop here and check logs — don't move to Nginx yet:
```bash
docker compose logs backend --tail=50
docker compose logs postgres --tail=20
```

---

## Step 5 — Configure Host Nginx

```bash
sudo nano /etc/nginx/sites-available/vanguard
```

```nginx
server {
    listen 80;
    server_name vanguard.cuetinsights.dev;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
    }
}
```

Why only one `location` block, unlike Spandan's config which had separate
blocks for `/`, `/api/`, etc.: the bundled `nginx` container running inside
Vanguard's own Docker stack already does that internal routing. Host Nginx's
only job here is "forward everything for this domain to port 8080" — the
container behind that port handles splitting `/api/`, `/ws`, and static
files itself.

`proxy_set_header Upgrade`/`Connection "upgrade"` — required because this
app uses WebSockets for the live map. Without these two lines, the
real-time updates won't work even though the rest of the site loads fine.

Enable it:
```bash
sudo ln -s /etc/nginx/sites-available/vanguard /etc/nginx/sites-enabled/
sudo nginx -t
```
Must print `syntax is ok` before continuing. If it errors, fix before
reloading — don't reload a broken config, it can take down your other
three apps' Nginx routing too since they share the same Nginx process.

```bash
sudo systemctl reload nginx
```

---

## Step 6 — SSL Certificate

You've hit the "cert doesn't exist yet" error twice before with Spandan and
CinemaSeat — the config above is deliberately HTTP-only for this exact
reason. Certbot needs to see the domain answering on port 80 first, then it
generates the cert and rewrites the config to add HTTPS automatically.

```bash
sudo certbot --nginx -d vanguard.cuetinsights.dev
```

Choose the redirect-to-HTTPS option when prompted. Verify:
```bash
sudo nginx -t && sudo systemctl status nginx
sudo certbot certificates
```
Should now show four certificates total (cinemaseat, sakawatkabir.me,
spandan, and now vanguard).

---

## Step 7 — Final Verification

```bash
curl https://vanguard.cuetinsights.dev/api/health
```

Open `https://vanguard.cuetinsights.dev` in a browser — you should see a
login screen. Log in with your `DASHBOARD_PASSWORD`.

Confirm the other three apps are still working (nothing should have broken,
but always worth a quick check after touching shared Nginx):
```bash
curl -I https://spandan.cuetinsights.dev
curl -I https://cinemaseat.cuetinsights.dev
curl -I https://sakawatkabir.me
```

---

## Step 8 — Install the Monitoring Agent

To have Vanguard actually watch traffic, install the agent on whichever
server's logs you want monitored (e.g. this same EC2, watching Spandan's
or CinemaSeat's nginx logs):

```bash
cd /var/www/vanguard-360/agent
cp .env.example .env
nano .env
```

```env
BACKEND_URL=https://vanguard.cuetinsights.dev
COLLECTOR_TOKEN=<paste the exact same value from vanguard-360/.env>
LOG_PATH=/var/log/nginx/access.log
SERVER_ID=ec2-shared-server
```

```bash
chmod +x install.sh
sudo ./install.sh
sudo journalctl -u vanguard-agent -f
```
Look for "Delivered N log events" — confirms it's shipping data successfully.

---

## Disk Space Note

Your `docker system df` showed 815MB of reclaimable build cache before this
deploy. After Vanguard's build adds more, clean it up:

```bash
docker builder prune -f
```
Safe — only removes unused build layers, never touches running containers
or images actually in use by any of your four apps.

---

## Quick Troubleshooting Reference

| Symptom | Check |
|---|---|
| `curl 127.0.0.1:8080` fails | `docker compose logs backend` — likely a `.env` secret still has a placeholder value |
| Login page loads but API calls fail | Confirm `CORS_ORIGINS=[]` and that you're accessing via `https://vanguard.cuetinsights.dev`, not the raw IP |
| WebSocket/live map not updating | Check the Nginx `Upgrade`/`Connection` headers are present exactly as shown in Step 5 |
| `nginx -t` fails after adding this config | Check no syntax typo in the new file — this Nginx process serves all four of your apps, a bad config here can affect the others too |
| Agent not delivering events | Check `BACKEND_URL` is the full `https://` domain, and `COLLECTOR_TOKEN` matches exactly between agent's `.env` and Vanguard's `.env` |
