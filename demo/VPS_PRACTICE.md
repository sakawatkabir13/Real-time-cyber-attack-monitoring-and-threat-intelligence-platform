# Hands-on practice on Spandan with Vanguard

Monitored website: **https://spandan.cuetinsights.dev**

Dashboard: **https://vanguard.cuetinsights.dev**

Run the commands below in your VPS's SSH terminal. They send real HTTPS
requests to Spandan, producing access logs for the existing collector to send
to Vanguard. The examples demonstrate signatures and authentication-failure
rules; the volume exercise is now a negative control. They
are not proof of a successful exploit or of ML accuracy.

## 1. Check the site's access log and collector

The VPS hosts multiple applications. Use a dedicated Spandan access log so the
collector does not mix the other apps with Spandan or collect Vanguard's own
ingestion/heartbeat requests repeatedly.

Inspect the effective Nginx configuration to locate Spandan's HTTPS server
block and existing logging directives:

```bash
sudo nginx -T 2>/dev/null | rg -n 'configuration file|server_name|access_log|log_format'
sudo systemctl status vanguard-agent --no-pager
```

If ripgrep (`rg`) is unavailable on the VPS, replace it with `grep -nE`.
These examples assume host Nginx, as in this project's VPS deployment guide.
If Spandan's proxy lives in Docker, locate its configuration and host-mounted
access log first; do not edit an unrelated host Nginx instance.

Use the actual configuration filename shown by `nginx -T` with `sudoedit`.
Inside **Spandan's existing HTTPS `server { ... }` block**, configure an access
log that uses the standard combined format. If the site already has its own
compatible log, keep its existing path and use that path below instead.

```nginx
access_log /var/log/nginx/spandan.access.log combined;
```

Do not overwrite the whole virtual-host configuration. Existing locations can
override or disable access logging; confirm the test requests actually reach the
chosen log. Keep existing TLS, proxy, and client-IP trust configuration intact.

For repeatable demonstrations, add these two exact locations inside the same
Spandan HTTPS server block. They return fixed text directly from Nginx and do
not call the application or database. They add a deliberate demonstration
authentication failure and a lightweight request-counting target.

```nginx
location = /api/login/vanguard-demo {
    access_log /var/log/nginx/spandan.access.log combined;
    default_type text/plain;
    add_header Cache-Control "no-store" always;
    return 401 "Vanguard demo authentication failure\n";
}

location = /vanguard-demo-volume {
    access_log /var/log/nginx/spandan.access.log combined;
    default_type text/plain;
    add_header Cache-Control "no-store" always;
    return 200 "Vanguard demo volume endpoint\n";
}
```

Use your selected log path consistently in these locations. Verify neither path
is already used by Spandan before adding it. The `/api/login/` prefix is
intentional: the current brute-force rule recognizes it as authentication traffic.

Validate before reloading Nginx:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

If the collector is installed through `agent/install.sh`, its configuration is
`/opt/vanguard-agent/.env`. First inspect the non-secret fields:

```bash
sudo rg '^(BACKEND_URL|SERVER_ID|LOG_PATH|SPOOL_PATH|START_AT_END)=' /opt/vanguard-agent/.env
```

The Spandan collector needs settings equivalent to:

```dotenv
BACKEND_URL=https://vanguard.cuetinsights.dev
LOG_PATH=/var/log/nginx/spandan.access.log
SERVER_ID=spandan-web
COLLECTOR_TOKEN=<the collector token configured on your Vanguard backend>
START_AT_END=true
```

Preserve a stable, existing Spandan server ID rather than replacing it. If this
service already monitors a different application, do not repurpose it: Spandan
needs its own collector process, configuration, and unique `SPOOL_PATH`.
The stock installer manages one service and should not be rerun blindly over
another application's collector.

For a service already assigned to Spandan, edit the necessary fields with
`sudoedit /opt/vanguard-agent/.env`, then restart and watch it:

```bash
sudo systemctl restart vanguard-agent
sudo journalctl -u vanguard-agent -f
```

Do not display the full `.env` or expose its token during the presentation.
If the agent is not installed, see `agent/install.sh` and
`VPS_DEPLOYMENT_GUIDE.md` for installation; the requests below require a working
collector or must be explained as website-only tests.

In another terminal, watch the selected log:

```bash
sudo tail -f /var/log/nginx/spandan.access.log
```

Confirm the collector appears as FORWARDING in Vanguard. If you are behind a
CDN/reverse proxy, verify the logged source is the actual client IP, using only
the existing trusted-proxy configuration. Do not spoof `X-Forwarded-For` to make
the map show invented locations. VPS-originated requests may appear as your
VPS's public IP; private addresses will not have a map location.

## 2. Define a convenient request command

Paste this into a VPS terminal once:

```bash
demo_request() {
  curl --noproxy '*' --connect-timeout 5 --max-time 10 \
    --silent --show-error --output /dev/null \
    --write-out 'HTTP %{http_code}\n' \
    --user-agent 'Mozilla/5.0 VanguardClassroom' \
    "https://spandan.cuetinsights.dev$1"
}
```

The function sends one request, prints the HTTP response status, and discards
the response body. It does not follow redirects. The self-identifying user agent
makes classroom requests recognizable. Ordinary curl requests are no longer
scanner evidence by themselves.

Watch the log, collector journal, and Vanguard's event table while running
each example once. Allow several seconds for collection and processing. Run
the volume exercise last: its counter includes earlier requests from your IP.

## 3. Ordinary traffic

```bash
demo_request '/?vanguard_demo=normal'
```

Expected: the site receives and logs the request. No rule detection is expected
from request count alone. A trained ML model
could still detect unusual window-level activity independently.

## 4. SQL injection indicator

```bash
demo_request '/?vanguard_demo=sqli&id=1+UNION+SELECT+1'
```

Expected rule: `sql_injection`, high severity. `UNION+SELECT` matches the current
URL signature. This demonstrates recognition of SQL-like input; it does not
establish whether Spandan interpreted it as a database query.

## 5. XSS indicator

```bash
demo_request '/?vanguard_demo=xss&q=%3Cscript%3Ealert(1)%3C/script%3E'
```

Expected rule: `xss`, high severity. The encoded script tag matches the current
pattern. No browser popup is needed. Curl does not execute JavaScript, and the
detector checks the logged request rather than observing script execution.

## 6. Path traversal indicator

```bash
demo_request '/?vanguard_demo=traversal&file=../../etc/passwd'
```

Expected rule: `path_traversal`, high severity. Putting the sequence in the query
preserves it for the current log parser. This is an attempted restricted-file
request indicator, not evidence that a file was read.

## 7. Sensitive-file reconnaissance

```bash
demo_request '/.env'
```

Expected rule: `scanner`, medium severity. HTTP 403 or 404 can still accompany a
detection, provided the request reaches the monitored access log. Do not add a
query string here: the current `.env` signature is anchored to the path's end.
Look in the **event table/live feed**; medium scanner events do not produce
persistent alerts under the current alert policy.

## 8. Repeated authentication failures

First confirm the temporary demo route returns **401** with the fixed demo text:

```bash
curl --noproxy '*' --connect-timeout 5 --max-time 10 -i \
  -A 'Mozilla/5.0 VanguardClassroom' \
  'https://spandan.cuetinsights.dev/api/login/vanguard-demo'
```

Then send up to 20 sequential requests, stopping on unexpected responses:

```bash
for attempt in {1..20}; do
  response=$(demo_request '/api/login/vanguard-demo') || break
  printf 'Attempt %s: %s\n' "$attempt" "$response"
  if [ "$response" != 'HTTP 401' ]; then
    printf 'Unexpected response. Stop and check the demo route and access log.\n'
    break
  fi
  sleep 1
done
```

Expected rule: `brute_force`, high severity, after more than 15 qualifying
failures in five minutes of request time and at least an 80% authentication-failure
ratio (default profile). The preliminary check also counts. No passwords are
submitted. Describe this honestly as a controlled demonstration of repeated
authentication failures, not an account compromise. A real login page returning
200, or an authentication API returning 400, would not satisfy this rule.

## 9. Request-volume negative control — run last

First confirm the temporary route returns **200** and `Vanguard demo volume endpoint`:

```bash
curl --noproxy '*' --connect-timeout 5 --max-time 10 -i \
  -A 'Mozilla/5.0 VanguardClassroom' \
  'https://spandan.cuetinsights.dev/vanguard-demo-volume'
```

Send a capped sequence of 110 lightweight requests, approximately one per second:

```bash
for request in {1..110}; do
  response=$(demo_request '/vanguard-demo-volume') || break
  printf 'Request %s/110: %s\n' "$request" "$response"
  if [ "$response" != 'HTTP 200' ]; then
    printf 'Unexpected response. Stop and check the endpoint.\n'
    break
  fi
  sleep 1
done
```

Expected: **no HTTP-flood rule warning from these successful, lightweight
responses alone**. Vanguard now requires supporting error/latency evidence
along with volume and path concentration. The former count-only critical
`ddos` rule has been replaced by a contextual `http_flood` warning.
This negative control demonstrates avoiding an obvious false alarm. A trained
ML model can still independently find unusual window-level behavior.

Do not use parallel flooding tools for this presentation. Stop with Ctrl+C at
any time. After this exercise, wait at least five minutes without additional
requests from that source before repeating other categories. Background
requests from the same source/server can also keep the counter elevated.

## 10. What to show and how to interpret results

For each example, show: request command → Spandan access-log entry → collector
delivery message → Vanguard event classification/explanation. HTTP response
status and detection severity are different: a suspicious request may be flagged
even if the site returns 200 or 404.

If a CDN/WAF blocks a request before it reaches the origin, it will not appear
in the origin log, and this collector cannot detect it. Verify the log before
diagnosing a missing event. A cached response can likewise bypass the origin.
Do not present an edge-blocked request as a Vanguard detection.

Enable Auto Refresh Feeds for WebSocket updates. Reload the page to check stored
events if a live update is missed. Persistent alerts may group repeated events
into one incident with an occurrence count.

These exercises test **rules and their negative controls**, not Isolation Forest. Rule scores such as 90
or 95 are fixed values, not ML confidence. An honest ML demonstration requires
the existing server's trained model, suitable later traffic, completed windows,
and actual inspected results. No single URL guarantees an ML finding.

After the presentation, remove only the two temporary demonstration locations
from Spandan's server block if no longer needed, then validate and reload Nginx.
Keep the dedicated access log and collector if you want ongoing monitoring.
Demo events and alerts already ingested remain in Vanguard until normal
retention cleanup. Nothing in this guide deletes existing events or volumes.
