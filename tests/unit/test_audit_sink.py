import json
from pathlib import Path

from server.audit.sink import AuditSink


def test_append_and_verify_chain(tmp_path: Path):
    sink = AuditSink(tmp_path)
    sink.append({"event": "OPERATION_PROPOSED", "approval_id": "appr_1"})
    sink.append({"event": "APPROVAL_GRANTED", "approval_id": "appr_1"})
    sink.append({"event": "EXECUTION_INTENT", "approval_id": "appr_1"})

    path = sink._path_for_today()
    assert sink.verify_chain(path) is True


def test_tampering_breaks_the_chain(tmp_path: Path):
    sink = AuditSink(tmp_path)
    sink.append({"event": "OPERATION_PROPOSED", "approval_id": "appr_1"})
    sink.append({"event": "APPROVAL_GRANTED", "approval_id": "appr_1"})

    path = sink._path_for_today()
    lines = path.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["approval_id"] = "appr_EVIL"  # tamper with the first record's content
    lines[0] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n")

    assert sink.verify_chain(path) is False


def test_entries_link_via_prev_hash(tmp_path: Path):
    sink = AuditSink(tmp_path)
    e1 = sink.append({"event": "A"})
    e2 = sink.append({"event": "B"})
    assert e2["prev_hash"] == e1["hash"]


def test_float_timestamps_do_not_crash(tmp_path: Path):
    import time

    sink = AuditSink(tmp_path)
    entry = sink.append({"event": "RUN_STARTED", "occurred_at": time.time(), "duration_ms": 12.5})
    assert "hash" in entry
    assert sink.verify_chain(sink._path_for_today()) is True
