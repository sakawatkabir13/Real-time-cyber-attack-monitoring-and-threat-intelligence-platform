import importlib.util
from pathlib import Path


def _load_agent_module():
    path = Path(__file__).with_name("agent.py")
    spec = importlib.util.spec_from_file_location("vanguard_agent", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def test_spool_and_cursor_survive_restart(tmp_path, monkeypatch):
    module = _load_agent_module()
    log_path = tmp_path / "access.log"
    spool_path = tmp_path / "spool.db"
    log_path.write_text(
        '203.0.113.2 - - [05/Aug/2026:01:00:00 +0000] "GET / HTTP/1.1" 200 12\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "SPOOL_PATH", str(spool_path))
    monkeypatch.setattr(module, "START_AT_END", False)
    monkeypatch.setattr(module.LogAgent, "_sender_loop", lambda self: self.stop_event.wait())

    first = module.LogAgent(str(log_path), "http://localhost", "token", "server-a")
    first.read_new_lines()
    assert first._queue_size() == 1
    first.close()

    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(
            '203.0.113.3 - - [05/Aug/2026:01:00:01 +0000] "GET /two HTTP/1.1" 200 13\n'
        )
    second = module.LogAgent(str(log_path), "http://localhost", "token", "server-a")
    second.read_new_lines()
    assert second._queue_size() == 2
    ids = [row[0] for row in second._next_batch()]
    assert len(ids) == len(set(ids)) == 2
    second.close()


def test_pause_command_is_persisted_without_deleting_spool(tmp_path, monkeypatch):
    module = _load_agent_module()
    log_path = tmp_path / "access.log"
    spool_path = tmp_path / "spool.db"
    log_path.write_text(
        '203.0.113.5 - - [05/Aug/2026:01:00:00 +0000] "GET / HTTP/1.1" 200 12\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "SPOOL_PATH", str(spool_path))
    monkeypatch.setattr(module, "START_AT_END", False)
    monkeypatch.setattr(module.LogAgent, "_sender_loop", lambda self: self.stop_event.wait())

    first = module.LogAgent(str(log_path), "http://localhost", "token", "server-a")
    first.read_new_lines()

    class Response:
        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {"desiredState": "paused", "commandVersion": 3}

    class Session:
        @staticmethod
        def post(*_args, **_kwargs):
            return Response()

    first._heartbeat(Session())
    assert first.desired_state == "paused"
    assert first._queue_size() == 1
    first.close()

    second = module.LogAgent(str(log_path), "http://localhost", "token", "server-a")
    assert second.desired_state == "paused"
    assert second.command_version == 3
    assert second._queue_size() == 1
    second.close()
