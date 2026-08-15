import json
import os
import signal
import sqlite3
import threading
import time
import uuid

import requests
from dotenv import load_dotenv
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

load_dotenv()

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost")
COLLECTOR_TOKEN = os.getenv("COLLECTOR_TOKEN", "")
LOG_PATH = os.getenv("LOG_PATH", "/var/log/nginx/access.log")
SERVER_ID = os.getenv("SERVER_ID", "default_server")
SPOOL_PATH = os.getenv("SPOOL_PATH", "/var/lib/vanguard-agent/spool.db")
START_AT_END = os.getenv("START_AT_END", "true").lower() in {"1", "true", "yes"}
BATCH_SIZE = max(1, int(os.getenv("BATCH_SIZE", "100")))
FLUSH_INTERVAL = max(0.5, float(os.getenv("FLUSH_INTERVAL", "5")))
MAX_SPOOL_EVENTS = max(BATCH_SIZE, int(os.getenv("MAX_SPOOL_EVENTS", "100000")))
HEARTBEAT_INTERVAL = max(5.0, float(os.getenv("HEARTBEAT_INTERVAL", "10")))
AGENT_VERSION = "2.0.0"


class LogEventHandler(FileSystemEventHandler):
    def __init__(self, log_path: str, agent: "LogAgent"):
        self.log_path = os.path.abspath(log_path)
        self.agent = agent

    def on_modified(self, event):
        if not event.is_directory and os.path.abspath(event.src_path) == self.log_path:
            self.agent.read_new_lines()

    def on_created(self, event):
        if not event.is_directory and os.path.abspath(event.src_path) == self.log_path:
            self.agent.reopen_created_file()


class LogAgent:
    def __init__(self, log_path: str, backend_url: str, token: str, server_id: str):
        self.log_path = os.path.abspath(log_path)
        self.backend_url = backend_url.rstrip("/")
        self.collector_token = token
        self.server_id = server_id
        self.stop_event = threading.Event()
        self.file_lock = threading.RLock()
        self.db_lock = threading.Lock()
        self.file = None
        self.inode = None

        spool_dir = os.path.dirname(os.path.abspath(SPOOL_PATH))
        os.makedirs(spool_dir, mode=0o750, exist_ok=True)
        self.db = sqlite3.connect(SPOOL_PATH, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS queue ("
            "id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at REAL NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS cursors ("
            "path TEXT PRIMARY KEY, inode INTEGER NOT NULL, offset INTEGER NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS agent_state ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self.db.commit()
        self.desired_state = self._load_state("desired_state", "running")
        self.command_version = int(self._load_state("command_version", "0"))
        self.last_error = None

        self.open_file()
        self.sender = threading.Thread(target=self._sender_loop, name="sender", daemon=True)
        self.sender.start()

    def _cursor(self):
        with self.db_lock:
            return self.db.execute(
                "SELECT inode, offset FROM cursors WHERE path = ?", (self.log_path,)
            ).fetchone()

    def _load_state(self, key: str, default: str) -> str:
        with self.db_lock:
            row = self.db.execute(
                "SELECT value FROM agent_state WHERE key = ?", (key,)
            ).fetchone()
            return row[0] if row else default

    def _save_state(self, key: str, value: str) -> None:
        with self.db_lock:
            self.db.execute(
                "INSERT INTO agent_state(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self.db.commit()

    def _save_cursor(self, inode: int, offset: int, *, commit: bool = True):
        self.db.execute(
            "INSERT INTO cursors(path, inode, offset) VALUES (?, ?, ?) "
            "ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset",
            (self.log_path, inode, offset),
        )
        if commit:
            self.db.commit()

    def open_file(self, *, rotated: bool = False):
        if self.file:
            self.file.close()
        self.file = None
        self.inode = None
        try:
            stat = os.stat(self.log_path)
            stream = open(self.log_path, "r", encoding="utf-8", errors="replace")
            cursor = self._cursor()
            if cursor and cursor[0] == stat.st_ino and cursor[1] <= stat.st_size:
                offset = cursor[1]
            elif rotated or not START_AT_END:
                offset = 0
            else:
                offset = stat.st_size
            stream.seek(offset)
            self.file = stream
            self.inode = stat.st_ino
            with self.db_lock:
                self._save_cursor(stat.st_ino, offset)
        except FileNotFoundError:
            return
        except OSError as exc:
            print(f"Unable to open {self.log_path}: {exc}", flush=True)

    @staticmethod
    def parse_log_line(line: str) -> dict:
        try:
            parsed = json.loads(line)
            return parsed if isinstance(parsed, dict) else {"raw_log": line, "type": "combined_log"}
        except json.JSONDecodeError:
            return {"raw_log": line, "type": "combined_log"}

    def _enqueue_line(self, line: str, offset: int):
        payload = self.parse_log_line(line)
        payload["event_id"] = uuid.uuid4().hex
        with self.db_lock:
            self.db.execute("BEGIN")
            self.db.execute(
                "INSERT INTO queue(id, payload, created_at) VALUES (?, ?, ?)",
                (payload["event_id"], json.dumps(payload), time.time()),
            )
            self._save_cursor(self.inode, offset, commit=False)
            self.db.commit()

    def _queue_size(self) -> int:
        with self.db_lock:
            return int(self.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0])

    def reopen_created_file(self):
        with self.file_lock:
            self.open_file(rotated=True)
            self.read_new_lines()

    def read_new_lines(self):
        with self.file_lock:
            if not self.file:
                self.open_file()
                if not self.file:
                    return
            try:
                stat = os.stat(self.log_path)
                if stat.st_ino != self.inode:
                    rotation_spool_size = self._queue_size()
                    while rotation_spool_size < MAX_SPOOL_EVENTS:
                        line = self.file.readline()
                        if not line:
                            break
                        if line.strip():
                            self._enqueue_line(line.rstrip("\n"), self.file.tell())
                            rotation_spool_size += 1
                    if rotation_spool_size >= MAX_SPOOL_EVENTS:
                        print("Spool limit reached while draining rotated log", flush=True)
                        return
                    self.open_file(rotated=True)
                elif stat.st_size < self.file.tell():
                    self.file.seek(0)
                    with self.db_lock:
                        self._save_cursor(self.inode, 0)
            except FileNotFoundError:
                return

            spool_size = self._queue_size()
            while self.file:
                if spool_size >= MAX_SPOOL_EVENTS:
                    print("Spool limit reached; pausing log reads until delivery recovers", flush=True)
                    break
                line = self.file.readline()
                if not line:
                    break
                if line.strip():
                    self._enqueue_line(line.rstrip("\n"), self.file.tell())
                    spool_size += 1
                else:
                    with self.db_lock:
                        self._save_cursor(self.inode, self.file.tell())

    def _next_batch(self) -> list[tuple[str, str]]:
        with self.db_lock:
            return self.db.execute(
                "SELECT id, payload FROM queue ORDER BY created_at, id LIMIT ?", (BATCH_SIZE,)
            ).fetchall()

    def _delete_batch(self, ids: list[str]):
        with self.db_lock:
            self.db.executemany("DELETE FROM queue WHERE id = ?", [(item,) for item in ids])
            self.db.commit()

    def _heartbeat(self, session: requests.Session) -> None:
        try:
            response = session.post(
                f"{self.backend_url}/api/collector/heartbeat",
                json={
                    "server_id": self.server_id,
                    "reported_state": self.desired_state,
                    "spool_depth": self._queue_size(),
                    "agent_version": AGENT_VERSION,
                    "last_error": self.last_error,
                },
                headers={"Authorization": f"Bearer {self.collector_token}"},
                timeout=10,
            )
            response.raise_for_status()
            payload = response.json()
            desired = payload.get("desiredState")
            version = payload.get("commandVersion")
            if desired not in {"running", "paused"} or not isinstance(version, int):
                raise ValueError("invalid collector command response")
            if desired != self.desired_state:
                print(f"Collector forwarding state changed to {desired}", flush=True)
            self.desired_state = desired
            self.command_version = version
            self._save_state("desired_state", desired)
            self._save_state("command_version", str(version))
            self.last_error = None
        except (requests.RequestException, ValueError) as exc:
            self.last_error = f"Heartbeat failed: {exc}"[:2000]
            print(self.last_error, flush=True)

    def _sender_loop(self):
        session = requests.Session()
        delay = FLUSH_INTERVAL
        next_delivery = 0.0
        next_heartbeat = 0.0
        while not self.stop_event.is_set():
            now = time.monotonic()
            if now >= next_heartbeat:
                self._heartbeat(session)
                next_heartbeat = time.monotonic() + HEARTBEAT_INTERVAL
                now = time.monotonic()

            if self.desired_state == "paused":
                self.stop_event.wait(min(1.0, HEARTBEAT_INTERVAL))
                continue
            if now < next_delivery:
                self.stop_event.wait(min(1.0, next_delivery - now))
                continue
            rows = self._next_batch()
            if not rows:
                self.stop_event.wait(min(FLUSH_INTERVAL, 1.0))
                continue
            payload = {
                "server_id": self.server_id,
                "events": [json.loads(row[1]) for row in rows],
            }
            try:
                response = session.post(
                    f"{self.backend_url}/api/ingest/batch",
                    json=payload,
                    headers={"Authorization": f"Bearer {self.collector_token}"},
                    timeout=20,
                )
                response.raise_for_status()
                self._delete_batch([row[0] for row in rows])
                print(f"Delivered {len(rows)} log events", flush=True)
                delay = FLUSH_INTERVAL
                next_delivery = 0.0
                self.last_error = None
            except requests.RequestException as exc:
                self.last_error = f"Delivery failed; retaining spool for retry: {exc}"[:2000]
                print(self.last_error, flush=True)
                next_delivery = time.monotonic() + delay
                delay = min(delay * 2, 300)
        session.close()

    def close(self):
        self.stop_event.set()
        self.sender.join(timeout=30)
        with self.file_lock:
            if self.file:
                self.file.close()
        with self.db_lock:
            self.db.close()


def main():
    if not COLLECTOR_TOKEN or COLLECTOR_TOKEN == "your_token_here":
        raise SystemExit("COLLECTOR_TOKEN must be configured")

    log_dir = os.path.dirname(os.path.abspath(LOG_PATH))
    if not os.path.isdir(log_dir):
        raise SystemExit(f"Log directory does not exist: {log_dir}")

    print(f"Starting agent. Monitoring {LOG_PATH}", flush=True)
    agent = LogAgent(LOG_PATH, BACKEND_URL, COLLECTOR_TOKEN, SERVER_ID)
    observer = Observer()
    observer.schedule(LogEventHandler(LOG_PATH, agent), path=log_dir, recursive=False)
    observer.start()

    def stop(*_):
        agent.stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not agent.stop_event.wait(1):
            agent.read_new_lines()
    finally:
        observer.stop()
        observer.join(timeout=10)
        agent.close()


if __name__ == "__main__":
    main()
