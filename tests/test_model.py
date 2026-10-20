import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from repair_tool.config import DEFAULTS, RepairError
from repair_tool.model import ModelClient
import repair_tool.model
import copy


def test_firmware_mode_uses_firmware_system_prompt(tmp_path, monkeypatch):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["firmware"]["mode"] = True
    cfg["model"].update({"base_url": "https://example.test/v1", "name": "test-model"})
    cfg["poc"]["path"] = "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    client = ModelClient(cfg, tmp_path)
    seen = {}

    def fake_receive(request, directory, stage, deadline):
        seen["body"] = json.loads(request.data)
        return {"choices": [{"finish_reason": "stop",
                             "message": {"content": '{"query":{"op":"elf_info"}}'}}]}

    monkeypatch.setattr(client, "receive", fake_receive)
    client.ask("localize", {}, tmp_path / "call")
    system = seen["body"]["messages"][0]["content"]
    assert "rehosted MIPS32 big-endian firmware" in system
    assert "read_files" not in system and "needs_build_change" not in system


@pytest.mark.parametrize("value", [None, False, True, {"reason": "Requires a build flag", "files": ["Makefile"]}])
def test_needs_build_change_optional_value(tmp_path, monkeypatch, value):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1", "name": "test-model"})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    client = ModelClient(cfg, tmp_path)
    output = {"diagnosis": "ok", "needs_build_change": value}
    monkeypatch.setattr(client, "receive", lambda *args: {
        "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(output)}}]})
    if value is None or value is False:
        assert client.ask("test", {}, tmp_path / "call") == output
    else:
        with pytest.raises(RepairError) as caught:
            client.ask("test", {}, tmp_path / "call")
        assert caught.value.status == "needs_build_change"
        assert json.loads(str(caught.value)) == value


@pytest.mark.parametrize("content,expected", [
    # Contract shape.
    ('{"op": "call_sites"}', {"op": "call_sites"}),
    # Markdown fence around the object (real run localize/1).
    ('```json\n{"query": {"op": "disassemble", "site": 42, "around": 16}}\n```',
     {"query": {"op": "disassemble", "site": 42, "around": 16}}),
    # Prose then a fenced object (real run localize/2 shape).
    ('Let me start by getting the registry.\n\n```json\n{"op": "call_sites"}\n```',
     {"op": "call_sites"}),
    # Prose around a bare object, no fence.
    ('Sure! Here is the object:\n{"evidence": ["e1"], "reasoning": "r"}\nDone.',
     {"evidence": ["e1"], "reasoning": "r"}),
    # Braces inside strings must not confuse the balanced extraction.
    ('text {"outer": "has } brace", "n": 1} tail {x}',
     {"outer": "has } brace", "n": 1}),
])
def test_load_model_json_shapes(content, expected):
    from repair_tool.model import _load_model_json
    assert _load_model_json(content) == expected


def test_load_model_json_rejects_garbage():
    from repair_tool.model import _load_model_json
    with pytest.raises(json.JSONDecodeError):
        _load_model_json("no json here at all")


@pytest.mark.parametrize("mode", ["success", "truncated", "deadline", "length"])
def test_stream_assembly_and_limits(tmp_path, monkeypatch, mode):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()

            def emit(delta, finish=None, usage=None):
                data = {"model": "glm-test", "choices": [{"index": 0, "delta": delta,
                                                           "finish_reason": finish}]}
                if usage:
                    data["usage"] = usage
                self.wfile.write(("data: " + json.dumps(data, ensure_ascii=False) + "\n\n").encode())
                self.wfile.flush()
            try:
                emit({"reasoning_content": "private reasoning"})
                emit({"content": '{"diagnosis":"中'})
                if mode == "deadline":
                    for _ in range(30):
                        time.sleep(0.1)
                        emit({"reasoning_content": "."})
                    return
                if mode == "truncated":
                    return
                emit({"content": '文 test-secret"}'},
                     "length" if mode == "length" else "stop", {"total_tokens": 20})
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": f"http://127.0.0.1:{server.server_port}/v1", "name": "glm-test",
                             "stream": True, "reasoning_effort": "high",
                             "total_timeout_seconds": 1,
                             "request_timeout_seconds": 1})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    client = ModelClient(cfg, tmp_path)
    started = time.monotonic()
    try:
        if mode == "success":
            result = client.ask("test", {}, tmp_path / "call")
            assert result["diagnosis"] == "中文 test-secret"
            saved = (tmp_path / "call" / "response.json").read_text(encoding="utf-8")
            assert "test-secret" not in saved and "private reasoning" not in saved
            assert client.calls[0]["usage"]["total_tokens"] == 20
        else:
            with pytest.raises(RepairError, match={"truncated": "without finish_reason",
                                                  "deadline": "total time limit", "length": "Incomplete"}[mode]) as caught:
                client.ask("test", {}, tmp_path / "call")
            if mode == "length":
                structured = json.loads(str(caught.value))
                assert structured["finish_reason"] == "length"
                assert structured["response_content_present"] is True
                assert "compact strict JSON object" in structured["rule"]
            if mode == "deadline":
                assert time.monotonic() - started < 2
        partial = json.loads((tmp_path / "call" / "partial-response.json").read_text(encoding="utf-8"))
        assert partial["content"].startswith('{"diagnosis":"中')
        assert partial["reasoning_chars"] > 0
        assert partial["connected"] is True
        assert partial["connected_seconds"] >= 0
        assert partial["first_byte_seconds"] >= 0
        assert len(requests) == 1
        assert requests[0]["reasoning_effort"] == "high"
        assert requests[0]["stream"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_timeout_never_replays_non_idempotent_generation(tmp_path, monkeypatch):
    calls = []

    def receive(*args):
        calls.append(args)
        raise TimeoutError("provider stall after accepting POST")

    cfg = copy.deepcopy(DEFAULTS)
    cfg["firmware"]["mode"] = True
    cfg["model"].update({"base_url": "https://example.test/v1",
                         "total_timeout_seconds": 900,
                         "request_timeout_seconds": 600,
                         "retries": 4})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    client = ModelClient(cfg, tmp_path)
    monkeypatch.setattr(client, "receive", receive)
    with pytest.raises(RepairError, match="was not replayed") as caught:
        client.ask("test", {}, tmp_path / "call")
    assert caught.value.status == "infrastructure_failed"
    assert len(calls) == 1
    assert client.calls[-1]["status"] == "failed"
    assert client.calls[-1]["error_status"] == "infrastructure_failed"
    assert json.loads((tmp_path / "model-calls.json").read_text())[-1][
        "status"] == "failed"


def test_request_timeout_limits_socket_waits_not_total_generation(
        tmp_path, monkeypatch):
    deadlines = []

    def receive(request, directory, stage, deadline):
        deadlines.append(deadline)
        return {"model": "glm-test", "usage": {"total_tokens": 2},
                "choices": [{"finish_reason": "stop",
                             "message": {"content": '{"diagnosis":"ok"}'}}]}

    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1",
                         "total_timeout_seconds": 900,
                         "request_timeout_seconds": 600,
                         "retries": 2})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    monkeypatch.setattr(repair_tool.model.time, "monotonic", lambda: 100.0)
    client = ModelClient(cfg, tmp_path)
    monkeypatch.setattr(client, "receive", receive)
    assert client.ask("test", {}, tmp_path / "call") == {"diagnosis": "ok"}
    assert deadlines == [1000.0]


def test_source_mode_preserves_configured_zero_byte_retries(
        tmp_path, monkeypatch):
    calls = []

    def receive(*args):
        calls.append(args)
        raise TimeoutError("temporary connection failure")

    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1",
                         "total_timeout_seconds": 900,
                         "request_timeout_seconds": 600,
                         "retries": 2})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    client = ModelClient(cfg, tmp_path)
    monkeypatch.setattr(client, "receive", receive)
    monkeypatch.setattr(repair_tool.model.time, "sleep", lambda _: None)
    with pytest.raises(RepairError, match="connection/timeout failure"):
        client.ask("test", {}, tmp_path / "call")
    assert len(calls) == 3


def test_external_workflow_deadline_clamps_model_request(tmp_path, monkeypatch):
    deadlines = []

    def receive(request, directory, stage, deadline):
        deadlines.append(deadline)
        return {"model": "glm-test", "usage": {"total_tokens": 2},
                "choices": [{"finish_reason": "stop",
                             "message": {"content": '{"diagnosis":"ok"}'}}]}

    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1",
                         "total_timeout_seconds": 900,
                         "request_timeout_seconds": 600})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    monkeypatch.setattr(repair_tool.model.time, "monotonic", lambda: 100.0)
    client = ModelClient(cfg, tmp_path)
    monkeypatch.setattr(client, "receive", receive)
    assert client.ask("test", {}, tmp_path / "call", deadline=180.0) == {
        "diagnosis": "ok"}
    assert deadlines == [180.0]


def test_expired_total_deadline_prevents_dispatch(tmp_path, monkeypatch):
    calls = []
    values = iter([100.0, 102.0])
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1",
                         "total_timeout_seconds": 1,
                         "request_timeout_seconds": 600})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    monkeypatch.setattr(repair_tool.model.time, "monotonic", lambda: next(values))
    client = ModelClient(cfg, tmp_path)
    monkeypatch.setattr(client, "receive", lambda *args: calls.append(args))
    with pytest.raises(RepairError, match="before dispatch"):
        client.ask("test", {}, tmp_path / "call")
    assert calls == []


def test_receive_cancellation_closes_response_and_joins_worker(tmp_path, monkeypatch):
    class BlockingResponse:
        def __init__(self):
            self.closed = threading.Event()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def read1(self, size):
            self.closed.wait(timeout=2)
            return b""

        def close(self):
            self.closed.set()

    response = BlockingResponse()

    class Opener:
        def open(self, request, timeout):
            return response

    monkeypatch.setattr(repair_tool.model.urllib.request, "build_opener",
                        lambda *args: Opener())
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1",
                         "total_timeout_seconds": 1,
                         "request_timeout_seconds": 1})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    directory = tmp_path / "call"
    directory.mkdir()
    request = repair_tool.model.urllib.request.Request("https://example.test")
    with pytest.raises(RepairError, match="total time limit"):
        ModelClient(cfg, tmp_path).receive(
            request, directory, "test", time.monotonic() + 0.05)
    partial = json.loads((directory / "partial-response.json").read_text())
    assert response.closed.is_set()
    assert partial["worker_stopped"] is True
    assert partial["connected"] is True
    assert partial["connected_seconds"] >= 0
    assert partial["first_byte_seconds"] is None


def test_unfinished_request_blocks_a_second_dispatch(tmp_path, monkeypatch):
    stop = threading.Event()
    previous = threading.Thread(target=stop.wait, daemon=True)
    previous.start()
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1",
                         "request_timeout_seconds": 1})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    client = ModelClient(cfg, tmp_path)
    client._active_worker = previous
    monkeypatch.setattr(
        repair_tool.model.urllib.request, "build_opener",
        lambda *args: pytest.fail("a second request must not be dispatched"))
    try:
        with pytest.raises(RepairError, match="still shutting down"):
            client.receive(
                repair_tool.model.urllib.request.Request("https://example.test"),
                tmp_path, "test", time.monotonic() + 1)
    finally:
        stop.set()
        previous.join(timeout=1)


def test_http_200_provider_error_is_infrastructure_failure(tmp_path, monkeypatch):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1",
                         "name": "glm-test"})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    client = ModelClient(cfg, tmp_path)
    monkeypatch.setattr(client, "receive", lambda *args: {
        "error": {"code": "provider_busy", "type": "server_error",
                  "message": "try later"}})
    with pytest.raises(RepairError, match="provider returned an error") as caught:
        client.ask("test", {}, tmp_path / "call")
    assert caught.value.status == "infrastructure_failed"
    assert client.calls[-1]["status"] == "failed"
    assert client.calls[-1]["error_status"] == "infrastructure_failed"
    saved = json.loads((tmp_path / "model-calls.json").read_text())
    assert saved[-1]["status"] == "failed"


def test_nonstream_requires_explicit_stop_finish_reason(tmp_path, monkeypatch):
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1",
                         "name": "glm-test", "stream": False})
    cfg["project"]["path"], cfg["poc"]["path"] = "project", "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    client = ModelClient(cfg, tmp_path)
    monkeypatch.setattr(client, "receive", lambda *args: {
        "choices": [{"finish_reason": None,
                     "message": {"content": '{"diagnosis":"partial"}'}}]})
    with pytest.raises(RepairError, match="Incomplete model output") as caught:
        client.ask("test", {}, tmp_path / "call")
    assert caught.value.status == "model_output_invalid"
    assert client.calls[-1]["status"] == "failed"


def test_actual_http_request_redaction_and_model_selection(tmp_path, monkeypatch):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            assert self.headers["Authorization"] == "Bearer test-secret"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"model": "actual-model", "usage": {"total_tokens": 12},
                "choices": [{"finish_reason": "stop", "message": {"content": '{"diagnosis":"ok"}'}}]}).encode())
        def log_message(self, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": f"http://127.0.0.1:{server.server_port}/v1", "name": "chosen-model"})
    cfg["project"]["path"] = str(tmp_path / "source")
    cfg["poc"]["path"] = str(tmp_path / "poc.py")
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    try:
        client = ModelClient(cfg, tmp_path)
        assert client.ask("test", {"code": "test-secret"}, tmp_path / "call")["diagnosis"] == "ok"
        assert requests[0]["model"] == "chosen-model"
        assert "test-secret" not in (tmp_path / "call" / "prompt.json").read_text()
        assert client.calls[0]["usage"]["total_tokens"] == 12
        partial = json.loads((tmp_path / "call" / "partial-response.json").read_text())
        progress = json.loads((tmp_path / "call" / "progress.json").read_text())
        assert partial["complete"] is True
        assert partial["finish_reason"] == "stop"
        assert partial["content"] == '{"diagnosis":"ok"}'
        assert json.loads(partial["raw_response"])["model"] == "actual-model"
        assert partial["received_bytes"] > 0 and partial["worker_stopped"] is True
        assert progress["complete"] is True
        assert progress["finish_reason"] == "stop"
        assert progress["received_bytes"] == partial["received_bytes"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_parameter_error_not_silently_retried(tmp_path, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        calls = 0
        def do_POST(self):
            Handler.calls += 1
            self.send_response(400)
            self.end_headers()
        def log_message(self, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": f"http://127.0.0.1:{server.server_port}/v1", "name": "chosen"})
    cfg["project"]["path"] = "project"
    cfg["poc"]["path"] = "poc"
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    try:
        with pytest.raises(RepairError, match="HTTP 400"):
            ModelClient(cfg, tmp_path).ask("test", {}, tmp_path / "call")
        assert Handler.calls == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
