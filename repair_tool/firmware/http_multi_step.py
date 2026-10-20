"""Bounded multi-step HTTP execution for management-plane firmware plans.

The runner is deliberately not a browser and not a scripting engine.  It
executes an ordered, validated list of HTTP requests, captures only declared
HTML input fields and cookies, and observes one explicitly declared empty-file
marker inside the session rootfs.  Nothing here grants arbitrary network,
filesystem, or shell access.
"""
from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Iterable

from ..config import RepairError
from ..storage import save_json
from .http import parse_response
from .protocol import (FORM_CONTENT_TYPE,
                       HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
                       MAX_FORM_FIELDS, MAX_FORM_VALUE_BYTES,
                       protocol_driver)

MAX_STEPS = 30
MAX_CAPTURE_FIELDS = 16
MAX_COOKIE_PAIRS = 16
MAX_MARKER_PATH_CHARS = 128
MAX_CONTAINS_BYTES = 4096
COMPLETE_RECEIVE_STATES = frozenset({"eof", "response", "complete", "timeout"})


@dataclass
class StepState:
    cookies: dict[str, str]
    captures: dict[str, str]


class _InputCaptureParser(HTMLParser):
    def __init__(self, names: set[str]):
        super().__init__(convert_charrefs=True)
        self.names = names
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        fields = {name.lower(): value or "" for name, value in attrs}
        name = fields.get("name")
        if name in self.names and name not in self.values:
            self.values[name] = fields.get("value", "")


def _field_name(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise RepairError("preparation_failed", f"{label} is invalid")
    if any(ord(char) <= 32 or ord(char) >= 127 or char in "\r\n\t" for char in value):
        raise RepairError(
            "preparation_failed",
            f"{label} must be ASCII without whitespace/control bytes")
    return value


def _statuses(value: object) -> list[int] | None:
    if value is None:
        return None
    if (not isinstance(value, list) or not value or len(value) > 20
            or any(type(item) is not int or not 100 <= item <= 599
                   for item in value)):
        raise RepairError("preparation_failed",
                          "statuses must contain HTTP codes 100..599")
    return value


def _contains(value: object) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_CONTAINS_BYTES:
        raise RepairError("preparation_failed",
                          "contains must be text up to 4096 UTF-8 bytes")
    return value


def _form_value(value: object, captures: set[str]) -> str | dict:
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_FORM_VALUE_BYTES:
            raise RepairError("preparation_failed", "Form value is too long")
        return value
    if isinstance(value, dict) and set(value) == {"capture"}:
        name = _field_name(value.get("capture"), "Capture field name")
        if name not in captures:
            raise RepairError(
                "preparation_failed",
                f"Form references uncaptured field {name!r}")
        return value
    raise RepairError("preparation_failed",
                      "Form values must be text or {'capture': name}")


def validate_marker(marker: object) -> str:
    if not isinstance(marker, str) or not marker.startswith("/") \
            or len(marker) > MAX_MARKER_PATH_CHARS or "\\" in marker or "\x00" in marker:
        raise RepairError("preparation_failed",
                          "marker must be a bounded absolute guest path")
    path = PurePosixPath(marker)
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise RepairError("preparation_failed", "marker path is not canonical")
    return marker


def validate_steps(steps: object, *, protocol: str) -> list[dict]:
    if protocol != HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80:
        raise RepairError(
            "protocol_unsupported",
            "Multi-step form scenarios require the registered form/auth protocol")
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise RepairError("preparation_failed",
                          f"A scenario requires 1..{MAX_STEPS} steps")
    driver = protocol_driver(protocol)
    ids: set[str] = set()
    clean: list[dict] = []
    available_captures: set[str] = set()
    allowed = {
        "id", "method", "path", "host", "port", "referer", "form",
        "content_type", "capture_cookies", "capture_fields", "expect",
        "statuses", "contains", "accept_timeout",
    }
    for step in steps:
        if not isinstance(step, dict) or set(step) - allowed:
            raise RepairError("preparation_failed", "Invalid multi-step fields")
        ident = _field_name(step.get("id"), "Step id").replace("-", "_")
        if not ident.isidentifier() or ident in ids:
            raise RepairError("preparation_failed", "Step ids must be unique identifiers")
        ids.add(ident)
        form_spec = step.get("form", {})
        if not isinstance(form_spec, dict) or len(form_spec) > MAX_FORM_FIELDS:
            raise RepairError("preparation_failed", "Invalid form object")
        capture_names = step.get("capture_fields", [])
        if not isinstance(capture_names, list) or len(capture_names) > MAX_CAPTURE_FIELDS:
            raise RepairError("preparation_failed", "Invalid capture_fields list")
        captures = {_field_name(name, "Capture field name") for name in capture_names}
        if len(captures) != len(capture_names):
            raise RepairError("preparation_failed", "Capture field names must be unique")
        form = {name: _form_value(value, available_captures)
                for name, value in form_spec.items()}
        request = {
            key: step[key] for key in
            ("method", "path", "host", "port", "referer", "cookies")
            if key in step
        }
        if form:
            request["form"] = {
                name: "" if isinstance(value, dict) else value
                for name, value in form.items()
            }
            request["content_type"] = step.get("content_type", FORM_CONTENT_TYPE)
        driver.validate_request(request)
        if step.get("content_type", FORM_CONTENT_TYPE) != FORM_CONTENT_TYPE:
            raise RepairError("preparation_failed", "Unsupported form content type")
        if step.get("capture_cookies", False) not in (True, False):
            raise RepairError("preparation_failed", "capture_cookies must be boolean")
        accept_timeout = step.get("accept_timeout", False)
        if accept_timeout not in (True, False):
            raise RepairError("preparation_failed", "accept_timeout must be boolean")
        if accept_timeout and (not step.get("contains")
                               or step.get("statuses") is None):
            raise RepairError(
                "preparation_failed",
                "accept_timeout requires explicit statuses and contains")
        if step.get("expect", "response") not in {
                "response", "marker_created", "marker_absent"}:
            raise RepairError("preparation_failed", "Invalid step expectation")
        contains = step.get("contains", "")
        _contains(contains)
        clean.append({
            **step,
            "form": form,
            "capture_fields": sorted(captures),
            "statuses": _statuses(step.get("statuses")),
            "contains": contains,
            "accept_timeout": accept_timeout,
        })
        available_captures.update(captures)
    return clean


def _marker_path(session: Path, marker: str) -> Path:
    guest = PurePosixPath(validate_marker(marker))
    path = session / "rootfs" / Path(*guest.parts[1:])
    current = session / "rootfs"
    try:
        root_mode = current.lstat().st_mode
        if not stat.S_ISDIR(root_mode) or stat.S_ISLNK(root_mode):
            raise OSError("session rootfs is not a directory")
        for part in guest.parts[1:-1]:
            current = current / part
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise OSError("marker parent is not an owned directory")
    except OSError as exc:
        raise RepairError("infrastructure_failed",
                          f"Invalid marker path in session: {exc}") from exc
    return path


def observe_marker(session: Path, marker: str) -> dict:
    path = _marker_path(session, marker)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return {"exists": False, "guest_path": marker}
    except OSError as exc:
        raise RepairError("infrastructure_failed",
                          f"Cannot observe marker: {exc}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise RepairError("infrastructure_failed",
                          "Marker must be a regular file, not a symlink or directory")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise RepairError("infrastructure_failed",
                          f"Cannot stat marker: {exc}") from exc
    return {"exists": True, "guest_path": marker,
            "regular_file": True, "size": size, "empty": size == 0}


def _clean_marker(session: Path, marker: str) -> bool:
    path = _marker_path(session, marker)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RepairError("infrastructure_failed",
                          f"Cannot inspect marker before cleanup: {exc}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode) or path.stat().st_size != 0:
        raise RepairError("infrastructure_failed",
                          "Refusing to clean a non-empty or non-regular marker")
    try:
        path.unlink()
        return True
    except OSError as exc:
        raise RepairError("infrastructure_failed",
                          f"Cannot clean declared marker: {exc}") from exc


def _cookie_values(parsed) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in parsed.headers.get(b"set-cookie", ()):
        pair = raw.split(b";", 1)[0].decode("ascii", "strict")
        name, separator, value = pair.partition("=")
        if not separator or not name or len(values) >= MAX_COOKIE_PAIRS:
            continue
        try:
            protocol_driver(HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80).validate_request(
                {"method": "GET", "path": "/", "cookies": {name: value}})
        except RepairError:
            continue
        values[name] = value
    return values


def _capture_inputs(body: bytes, names: Iterable[str]) -> dict[str, str]:
    wanted = set(names)
    parser = _InputCaptureParser(wanted)
    try:
        parser.feed(body.decode("utf-8", "replace"))
        parser.close()
    except Exception:
        return {}
    return {name: value for name, value in parser.values.items()
            if len(value.encode("utf-8")) <= MAX_FORM_VALUE_BYTES}


def _resolve_form(spec: dict, state: StepState) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for name, value in spec.items():
        if isinstance(value, dict):
            try:
                value = state.captures[value["capture"]]
            except KeyError as exc:
                raise RepairError(
                    "reproduction_failed",
                    f"Captured field {value['capture']!r} is missing") from exc
        resolved[name] = value
    return resolved


def _delivery_complete(delivery: dict) -> bool:
    receive = delivery.get("receive")
    if receive == "timeout":
        return delivery.get("http_complete") is True
    return (receive in COMPLETE_RECEIVE_STATES
            and delivery.get("http_complete", True) is True)


def _step_failed(record: dict, reason: str) -> dict:
    record.update(status="failed", reason=reason)
    return record


def execute_steps(control, steps: object, *, protocol: str,
                  phase: str = "baseline", marker: str | None = None,
                  exit_timeout: float = 10.0,
                  deadline: float | None = None) -> dict:
    """Execute a bounded scenario and return observation records.

    In ``baseline`` phase, a step may expect ``marker_created``.  In
    ``candidate`` and ``fixed`` phases every step must respond and the marker
    must remain absent after every request.
    """
    from .tests import _observe_exits

    if phase not in {"baseline", "candidate", "fixed"}:
        raise RepairError("preparation_failed", "Invalid multi-step phase")
    clean_steps = validate_steps(steps, protocol=protocol)
    state = StepState(cookies={}, captures={})
    marker_cleaned_at_start = False
    marker_before: dict | None = None
    if marker is not None:
        marker_before = observe_marker(control.session, marker)
        marker_cleaned_at_start = _clean_marker(control.session, marker)
    target_start = control.current_target()
    results: list[dict] = []
    try:
        for item in clean_steps:
            current = control.current_target()
            if current.get("sha256") != target_start.get("sha256"):
                raise RepairError("integrity_failed",
                                  "Target bytes changed during HTTP scenario")
            form = _resolve_form(item.get("form", {}), state)
            request = {key: item[key] for key in
                       ("method", "path", "host", "port", "referer")
                       if key in item}
            if form:
                request["form"] = form
                request["content_type"] = item.get(
                    "content_type", FORM_CONTENT_TYPE)
            if state.cookies:
                request["cookies"] = dict(sorted(state.cookies.items()))
            exits_before = len(control.target_exits())
            delivery = control.deliver(
                request, timeout=max(0.0, float(exit_timeout)),
                protocol=protocol)
            new_exits = _observe_exits(
                control, exits_before, exit_timeout, deadline=deadline)
            response = bytes.fromhex(delivery.get("response_hex", ""))
            method = request.get("method", "GET")
            parsed = parse_response(response, method)
            record = {
                "id": item["id"],
                "expect": item.get("expect", "response"),
                "request": request,
                "capture_cookies": bool(item.get("capture_cookies", False)),
                "capture_fields": list(item.get("capture_fields", [])),
                "delivery": {key: delivery.get(key)
                             for key in ("bytes", "sha256", "receive", "protocol")},
                "http_status": parsed.status if parsed is not None else None,
                "exits": new_exits,
            }
            if marker is not None:
                record["marker_after"] = observe_marker(control.session, marker)
            if new_exits:
                results.append(_step_failed(record, "target_exited"))
                break
            statuses = item.get("statuses")
            contains = item.get("contains", "")
            timeout_accepted = (
                delivery.get("receive") == "timeout"
                and item.get("accept_timeout") is True
                and statuses is not None
                and parsed is not None
                and parsed.status in statuses
                and bool(contains)
                and contains.encode("utf-8") in parsed.body
            )
            if (not _delivery_complete(delivery) and not timeout_accepted) \
                    or parsed is None:
                results.append(_step_failed(record, "incomplete_response"))
                break
            if statuses is not None and parsed.status not in statuses:
                results.append(_step_failed(record, "http_status_mismatch"))
                break
            if contains and contains.encode("utf-8") not in parsed.body:
                results.append(_step_failed(record, "contains_mismatch"))
                break
            if item.get("capture_cookies", False):
                captured_cookies = _cookie_values(parsed)
                record["captured_cookies"] = sorted(captured_cookies)
                if not captured_cookies:
                    results.append(_step_failed(record, "missing_cookie"))
                    break
                state.cookies.update(captured_cookies)
                if len(state.cookies) > MAX_COOKIE_PAIRS:
                    results.append(_step_failed(record, "too_many_cookies"))
                    break
            wanted = item.get("capture_fields", [])
            captured = _capture_inputs(parsed.body, wanted)
            missing = [name for name in wanted if name not in captured]
            if missing:
                results.append(_step_failed(
                    record, "missing_capture_fields:" + ",".join(missing)))
                break
            state.captures.update(captured)
            expect = item.get("expect", "response")
            if phase == "baseline" and expect == "marker_created":
                after = record.get("marker_after", {})
                if not after.get("exists") or not after.get("empty"):
                    results.append(_step_failed(record, "marker_not_created"))
                    break
            elif ((phase != "baseline" or expect == "marker_absent")
                  and marker is not None
                  and record.get("marker_after", {}).get("exists")):
                results.append(_step_failed(record, "unexpected_marker"))
                break
            record["status"] = "ok"
            record["reason"] = None
            results.append(record)
        try:
            target_end = control.current_target()
        except RepairError:
            target_end = {"state": "unavailable"}
        stable = (target_end.get("pid") == target_start.get("pid")
                  and target_end.get("sha256") == target_start.get("sha256"))
        return {
            "phase": phase,
            "protocol": protocol,
            "marker": marker,
            "marker_before": marker_before,
            "marker_cleaned_at_start": marker_cleaned_at_start,
            "target_start": target_start,
            "target_end": target_end,
            "stable_identity": stable,
            "results": results,
            "passed": bool(results) and len(results) == len(clean_steps) and stable
                      and all(item["status"] == "ok" for item in results),
        }
    finally:
        if marker is not None:
            try:
                _clean_marker(control.session, marker)
            except RepairError:
                # Observation already recorded the unsafe/stuck marker.  Do
                # not replace a reproduction verdict with cleanup noise.
                pass


def marker_scenario_passed(report: dict, *, phase: str) -> bool:
    if not report.get("passed"):
        return False
    if phase != "baseline":
        return all(not step.get("marker_after", {}).get("exists")
                   for step in report.get("results", []))
    confirmed = [
        step for step in report.get("results", [])
        if step.get("expect") == "marker_created"
        and step.get("marker_after", {}).get("exists")
        and step.get("marker_after", {}).get("empty")
    ]
    return bool(confirmed)


def save_progress(path: Path, report: dict) -> None:
    safe = json.loads(json.dumps(report, ensure_ascii=False, default=str))
    save_json(path, safe)
