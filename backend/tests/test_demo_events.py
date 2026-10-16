from datetime import datetime, timezone

from generate_demo_events import generate_events


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


def test_single_and_distributed_dos_have_rule_evidence():
    single = generate_events("single-dos", now=NOW)
    distributed = generate_events("distributed-dos", now=NOW)
    assert len(single) == 120
    assert len({event["source_ip"] for event in single}) == 1
    assert all(event["status_code"] == 503 and event["request_time"] == 4.5 for event in single)
    assert len(distributed) == 960
    assert len({event["source_ip"] for event in distributed}) == 8
    assert all(event["path"] == "/api/expensive" for event in distributed)


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
