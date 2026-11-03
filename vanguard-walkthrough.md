## Clone the repository

```bash 
git clone https://github.com/sakawatkabir13/Real-time-cyber-attack-monitoring-and-threat-intelligence-platform.git
cd Real-time-cyber-attack-monitoring-and-threat-intelligence-platform
```

## Prepare real map source identities

```bash
export BACKEND_URL="https://vanguard.cuetinsights.dev"
export COLLECTOR_TOKEN="d3b6add292be455608773fc201ba04b9853b91ec090870b23112571fd986dd2a"
export DEMO_IPS_FILE=./vanguard-demo-diverse-ips.txt 
```

## Demonstrate Normal Traffic 

```bash
for i in {1..10}; do \
curl https://spandan.cuetinsights.dev; \
sleep 0.01;
done 
```

## Rule-based HTTP detections

Run each scenario separately and wait for its events to appear.

### Scanner/reconnaissance

```bash
python3 backend/generate_demo_events.py \
  --scenario scanner \
  --server-id spandan-web \
  --source-ips "$(sed -n '15p' "$DEMO_IPS_FILE")" \
  --send --backend-url "$BACKEND_URL" --token "$COLLECTOR_TOKEN"
```

Expected: `scanner`, medium severity, multiple detections from one source.
Show the path, `feroxbuster` user-agent, source country, and map arc. The
generator intentionally keeps scanner requests on one source; repeat the
command with another line number if you want another scanner origin.

### SQL injection, XSS, path traversal, and brute force

```bash
python3 backend/generate_demo_events.py --scenario sql-injection --server-id spandan-web --source-ips "$(sed -n '1p' "$DEMO_IPS_FILE")" --send --backend-url "$BACKEND_URL" --token "$COLLECTOR_TOKEN"
python3 backend/generate_demo_events.py --scenario xss --server-id spandan-web --source-ips "$(sed -n '2p' "$DEMO_IPS_FILE")" --send --backend-url "$BACKEND_URL" --token "$COLLECTOR_TOKEN"
python3 backend/generate_demo_events.py --scenario path-traversal --server-id spandan-web --source-ips "$(sed -n '3p' "$DEMO_IPS_FILE")" --send --backend-url "$BACKEND_URL" --token "$COLLECTOR_TOKEN"
python3 backend/generate_demo_events.py --scenario brute-force --server-id spandan-web --source-ips "$(sed -n '9p' "$DEMO_IPS_FILE")" --send --backend-url "$BACKEND_URL" --token "$COLLECTOR_TOKEN"
```

Expected: `sql_injection`, `xss`, `path_traversal`, and `brute_force` events
from different demonstration identities. Brute force remains one source so
the repeated authentication failures form one behavioral pattern.

## single-source and distributed HTTP floods

These are simulated with HTTP 503 responses and slow request times. They are
not real network floods.

For the best map presentation, keep the map open and leave **Pause animation**
off. The distributed scenario below gives every source the same event
timestamp, so the dashboard receives a synchronized burst from many origins.
Vanguard still accepts the records in safe HTTP batches; the timestamps make
the attack pattern simultaneous without sending a real flood to Spandan.

### Single-source HTTP DoS

```bash
python3 backend/generate_demo_events.py \
  --scenario single-dos \
  --server-id spandan-web \
  --source-ips "$(sed -n '7p' "$DEMO_IPS_FILE")" \
  --send --backend-url "$BACKEND_URL" --token "$COLLECTOR_TOKEN"
```

Expected: a high-severity `http_flood` finding from one source.

### Distributed HTTP DDoS pattern

```bash
python3 backend/generate_demo_events.py \
  --scenario distributed-dos \
  --server-id spandan-web \
  --source-ips-file "$DEMO_IPS_FILE" \
  --send --backend-url "$BACKEND_URL" --token "$COLLECTOR_TOKEN"
```

Expected: up to 16 `http_flood` findings from different source countries,
parallel source-to-server arcs arriving together, and a related incident
group. With the prepared 128-address pool, the generator uses the first 16
geolocatable identities and creates 120 timestamp-matched requests per source.
The map playback starts timestamp-matched routes in the same animation frame,
so the visual result is a Norse-style simultaneous fan rather than one source
appearing long after the others. Dashboard and Threat Map use the same large
map canvas and route animation; only the dedicated Threat Map has the separate
recent-detections panel.

## Unknown aggregate pattern: server-level ML

This uses ordinary-looking successful requests. No individual request contains
an SQL, scanner, XSS, traversal, or flood signature. The unusual behavior is
visible only after the requests are aggregated.

```bash
python3 backend/generate_demo_events.py \
  --scenario ml-burst \
  --server-id spandan-web \
  --source-ips-file "$DEMO_IPS_FILE" \
  --send --backend-url "$BACKEND_URL" --token "$COLLECTOR_TOKEN"
```

Wait approximately 80–120 seconds. The window will be scored even when it does
not become an alert. In the current presentation model, this scenario produced
384 requests from 32 sources and an ML score of `77.44`; the previous alert
threshold was `90`, so that run was correctly scored but did not create a
persisted `server_traffic_anomaly` event. Do not describe a below-threshold
score as a failed ingestion.

When the score crosses the configured threshold, expected:

- `server_traffic_anomaly`
- an ML anomaly score and explanation
- an aggregate finding with `Multiple sources`
- a pulsing ML aggregate marker at the monitored server
- no single source arc for that aggregate event, because the finding has no
  single attacker IP

Suggested narration:

> “No individual request contains a known attack signature. The unusual
> behavior appears only when the requests are analyzed together. That is what
> the server-level behavioral ML layer detects.”

For source-to-server arcs, use the distributed rule demo or the source-level
ML demo below. A server-level ML finding intentionally represents the whole
traffic window, so drawing one origin arc for it would be misleading.
