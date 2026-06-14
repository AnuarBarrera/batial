# cybersec/tests/test_tracing.py
import json
from cybersec.infrastructure.tracing import RunTracer


def test_record_writes_json_line_with_event_and_fields(tmp_path):
    path = tmp_path / "trace.jsonl"
    tracer = RunTracer(path)
    tracer.record("run_start", host="localhost", max_iterations=10)
    tracer.close()

    lines = path.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["event"] == "run_start"
    assert entry["host"] == "localhost"
    assert entry["max_iterations"] == 10
    assert "ts" in entry


def test_record_writes_one_line_per_call(tmp_path):
    path = tmp_path / "trace.jsonl"
    tracer = RunTracer(path)
    tracer.record("run_start", host="localhost")
    tracer.record("loop_end", reason="no_tool_calls", iteration=1)
    tracer.close()

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event"] == "run_start"
    assert json.loads(lines[1])["event"] == "loop_end"


def test_record_handles_non_serializable_values(tmp_path):
    path = tmp_path / "trace.jsonl"
    tracer = RunTracer(path)
    tracer.record("tool_call", payload=b"\x00\x01")
    tracer.close()

    lines = path.read_text().splitlines()
    entry = json.loads(lines[0])
    assert entry["event"] == "tool_call"
    assert "payload" in entry


def test_context_manager_closes_file(tmp_path):
    path = tmp_path / "trace.jsonl"
    with RunTracer(path) as tracer:
        tracer.record("run_start", host="localhost")

    lines = path.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "run_start"
