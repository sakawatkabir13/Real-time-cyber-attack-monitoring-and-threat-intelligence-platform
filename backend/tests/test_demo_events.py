from datetime import datetime, timezone
from pathlib import Path

from generate_demo_events import generate_events, main


NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)


def test_ml_burst_stays_below_per_source_rule_threshold():
    events = generate_events("ml-burst", now=NOW)
    assert len(events) == 384
    counts = {}
    for event in events:
        counts[event["source_ip"]] = counts.get(event["source_ip"], 0) + 1
        assert event["status_code"] == 200
        assert event["path"] == "/"
    assert max(counts.values()) < 100
    assert len(counts) == 8


def test_ml_source_burst_stays_below_rule_threshold_and_uses_many_sources():
    events = generate_events("ml-source-burst", source_ips=[f"1.1.1.{i}" for i in range(1, 20)], now=NOW)
    assert len(events) == 16 * 95
    counts = {}
    for event in events:
        counts[event["source_ip"]] = counts.get(event["source_ip"], 0) + 1
        assert event["status_code"] == 200
        assert event["path"] == "/"
    assert set(counts.values()) == {95}
    assert len(counts) == 16



def test_single_and_distributed_dos_have_rule_evidence():
    single = generate_events("single-dos", now=NOW)
    distributed = generate_events("distributed-dos", now=NOW)
    assert len(single) == 120
    assert len({event["source_ip"] for event in single}) == 1
    assert all(event["status_code"] == 503 and event["request_time"] == 4.5 for event in single)
    assert len(distributed) == 960
    assert len({event["source_ip"] for event in distributed}) == 8
    assert len({event["timestamp"] for event in distributed}) == 1
    assert all(event["path"] == "/api/expensive" for event in distributed)


def test_distributed_dos_uses_more_sources_when_a_diverse_pool_is_available():
    source_ips = [f"1.1.1.{i}" for i in range(1, 25)]
    events = generate_events("distributed-dos", source_ips=source_ips, now=NOW)
    assert len(events) == 16 * 120
    assert len({event["source_ip"] for event in events}) == 16
    assert len({event["timestamp"] for event in events}) == 1


def test_rule_scenarios_have_expected_signatures():
    assert "UNION+SELECT" in generate_events("sql-injection", now=NOW)[0]["path"]
    assert "%3Cscript%3E" in generate_events("xss", now=NOW)[0]["path"]
    assert "../" in generate_events("path-traversal", now=NOW)[0]["path"]
    brute_force = generate_events("brute-force", now=NOW)
    assert len(brute_force) == 20
    assert all(event["path"] == "/login" and event["status_code"] == 401 for event in brute_force)
    scanner = generate_events("scanner", now=NOW)
    assert len(scanner) == 20
    assert all("feroxbuster" in event["user_agent"] for event in scanner)


def test_cli_reads_and_deduplicates_public_source_ip_file(tmp_path: Path, monkeypatch):
    source_file = tmp_path / "source-ips.txt"
    source_file.write_text("1.1.1.1\n8.8.8.8\n8.8.8.8\n", encoding="utf-8")
    output = tmp_path / "events.jsonl"
    monkeypatch.setattr("sys.argv", [
        "generate_demo_events.py", "--scenario", "ml-burst",
        "--source-ips-file", str(source_file), "--output", str(output),
    ])
    assert main() == 0
    assert output.exists()
