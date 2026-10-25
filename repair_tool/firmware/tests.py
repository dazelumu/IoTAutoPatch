"""Declarative HTTP tests with a baseline oracle.

Three kinds, mirroring the C-source pipeline's taxonomy:
  regression    - must PASS on the original (baseline) firmware
  vulnerability - must trigger a fatal exit on the original firmware
                  (the same fault class the reproduction confirmed)
  independent   - holdout split; never shown to the model during repair,
                  executed only in final verification

A test is pure data (request + expectation); the executor delivers it through
the session channel and compares against observed facts. The baseline oracle
runs each test against the ORIGINAL target before any repair: pass-kind tests
must pass, crash-kind tests must produce an attributable fatal exit. Only a
test whose baseline behaved exactly as declared can later judge a candidate.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from ..config import RepairError
from ..storage import save_json
from .http import parse_response
from .rehost import FATAL_SIGNALS, SessionControl

TEST_KINDS = ("regression", "vulnerability", "independent")
MAX_TESTS = 50
TEST_ID = re.compile(r"[a-z0-9_-]{1,64}")
COMPLETE_RECEIVE_STATES = frozenset({"eof", "response", "complete", "timeout"})


def delivery_complete(delivery: dict) -> bool:
    """Whether the HTTP tunnel observed a complete response.

    A close-delimited response received on a socket timeout is incomplete, but
    ``timeout`` can be accepted when ``http_complete`` proves complete
    Content-Length, chunked, HEAD, 204, or 304 framing.
    """
    receive = delivery.get("receive")
    if receive == "timeout":
        return delivery.get("http_complete") is True
    return (receive in COMPLETE_RECEIVE_STATES
            and delivery.get("http_complete", True) is True)


def _timeout_within_deadline(timeout: float,
                             deadline: float | None) -> float:
    """Bound a local wait by an optional absolute firmware deadline."""
    timeout = max(0.0, float(timeout))
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RepairError("infrastructure_failed",
                          "firmware.total_timeout_seconds exceeded")
    return min(timeout, remaining)


def _observe_exits(control: SessionControl, before: int,
                   timeout: float, *,
                   deadline: float | None = None) -> list[dict]:
    """Observe the whole requested window and return exits after *before*."""
    # An abbreviated survival window cannot establish the requested verdict.
    if deadline is not None and deadline - time.monotonic() < timeout:
        raise RepairError("infrastructure_failed",
                          "firmware.total_timeout_seconds exceeded")
    timeout = _timeout_within_deadline(timeout, deadline)
    observation_deadline = time.monotonic() + timeout
    while True:
        new = control.target_exits()[before:]
        if new:
            return new
        now = time.monotonic()
        if deadline is not None and now >= deadline:
            raise RepairError("infrastructure_failed",
                              "firmware.total_timeout_seconds exceeded")
        if now >= observation_deadline:
            return []
        sleep_for = min(0.1, observation_deadline - now)
        if deadline is not None:
            sleep_for = min(sleep_for, max(0.0, deadline - now))
        if sleep_for <= 0:
            return new
        time.sleep(sleep_for)


def _step_identity(step: dict) -> dict:
    item = {key: step.get(key) for key in (
        "id", "method", "path", "host", "port", "referer", "form",
        "content_type", "capture_cookies", "capture_fields", "expect",
        "accept_timeout")}
    # validate_steps supplies this default whenever a form is present.  A
    # model may either omit it or spell the exact default explicitly; both
    # produce identical wire bytes and must not fail verbatim matching.
    if item.get("form") and item.get("content_type") == \
            "application/x-www-form-urlencoded":
        item["content_type"] = None
    return item


def required_trigger_scenarios(reproduction: dict, plan: dict | None) -> list[dict]:
    """Build controller-owned scenarios that generated tests must preserve.

    Model calls are stateless.  The reproduction summary is useful feedback,
    but a marker vulnerability test must replay the exact authenticated plan
    prefix through the confirmed trigger, including dynamic capture fields.
    """
    if not isinstance(plan, dict):
        return []
    marker_mode = reproduction.get("outcome") == "command_injection_marker"
    confirmed_ids = list(reproduction.get("confirmed_ids") or [])
    if not confirmed_ids:
        confirmed_ids = list(plan.get("confirmations") or [])
    scenarios = []
    steps = plan.get("requests")
    if not isinstance(steps, list):
        return scenarios
    for trigger_id in confirmed_ids:
        prefix = []
        found = False
        for step in steps:
            if not isinstance(step, dict):
                break
            prefix.append(step)
            if step.get("id") == trigger_id:
                found = True
                break
        if not found:
            continue
        if marker_mode:
            from .http_multi_step import validate_steps
            from .protocol import HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80
            scenario = {
                "protocol": HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
                "steps": validate_steps(
                    prefix, protocol=HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80),
                "marker": reproduction.get("marker") or plan.get("marker"),
            }
        else:
            trigger = prefix[-1]
            scenario = {
                "request": {key: trigger[key] for key in ("method", "path")
                            if key in trigger}
            }
        scenarios.append(scenario)
    return scenarios


def _inherit_confirmed_step_timing(steps: object,
                                   scenarios: list[dict]) -> object:
    """Carry confirmed response-framing semantics into copied pass steps.

    A model may correctly reuse a confirmed GET/POST path but omit the neutral
    ``accept_timeout`` framing fact observed during reproduction.  That turns
    a known complete framed timeout into a false ``incomplete_response`` in
    the baseline oracle.  Missing timing/assertion fields are inherited only
    when method and path match a confirmed step; an explicit contradictory
    false remains an error.
    """
    if not isinstance(steps, list):
        return steps
    sources: dict[tuple[str, str], dict] = {}
    for scenario in scenarios:
        candidate_steps = scenario.get("steps")
        if not isinstance(candidate_steps, list):
            continue
        for step in candidate_steps:
            if (isinstance(step, dict)
                    and step.get("accept_timeout") is True
                    and isinstance(step.get("method"), str)
                    and isinstance(step.get("path"), str)):
                sources[(step["method"], step["path"])] = step
    if not sources:
        return steps
    result = []
    for step in steps:
        if not isinstance(step, dict):
            result.append(step)
            continue
        source = sources.get((step.get("method"), step.get("path")))
        if source is None:
            result.append(step)
            continue
        item = dict(step)
        if item.get("accept_timeout") is False:
            raise RepairError(
                "model_output_invalid",
                "A pass test reusing a confirmed request path cannot "
                "contradict its observed accept_timeout=true framing")
        item.setdefault("accept_timeout", True)
        item.setdefault("statuses", list(source.get("statuses") or []))
        if not item.get("contains") and source.get("contains"):
            item["contains"] = source["contains"]
        result.append(item)
    return result


def _reject_collapsed_framed_step(request: dict,
                                  scenarios: list[dict]) -> None:
    """A request needing an authenticated/timeout-framed prefix cannot be
    collapsed into a standalone request using the default HTTP driver."""
    for scenario in scenarios:
        steps = scenario.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if (isinstance(step, dict)
                    and step.get("accept_timeout") is True
                    and step.get("method") == request.get("method", "GET")
                    and step.get("path") == request.get("path")):
                raise RepairError(
                    "model_output_invalid",
                    "A confirmed multi-step request with accept_timeout=true "
                    "must be replayed as its complete step scenario; do not "
                    "collapse it to a standalone request")


def _normalize_step_aliases(steps: object) -> object:
    """Accept one unambiguous spelling used by models for form content type.

    ``form_encoding`` is mapped to the contract's ``content_type`` before the
    closed field validation.  No new field values or request semantics are
    accepted here; ``validate_steps`` remains the authority.
    """
    if not isinstance(steps, list):
        return steps
    normalized = []
    for step in steps:
        if not isinstance(step, dict) or "form_encoding" not in step:
            normalized.append(step)
            continue
        item = dict(step)
        encoding = item.pop("form_encoding")
        if "content_type" in item and item["content_type"] != encoding:
            raise RepairError("model_output_invalid",
                              "form_encoding conflicts with content_type")
        item["content_type"] = encoding
        normalized.append(item)
    return normalized


def _canonical_confirmed_trigger(steps: list[dict] | None, entry: dict,
                                 scenarios: list[dict]) -> list[dict] | None:
    """Materialize a model-identified trigger from controller-owned bytes.

    A model batch must still explicitly choose the confirmed vulnerability
    trigger.  Once its marker and final request identity (method, path and
    form values) match a reproduced scenario, missing default spelling such
    as host or per-step expect is filled from the authoritative reproduction
    plan rather than trusting a retyped prefix.  A changed payload or path is
    not canonicalized and later fails the verbatim-scenario check.
    """
    if entry.get("kind") != "vulnerability" or not isinstance(steps, list):
        return steps
    for required in scenarios:
        expected_steps = required.get("steps")
        if not isinstance(expected_steps, list) or not expected_steps:
            continue
        final = expected_steps[-1]
        actual_final = steps[-1] if steps else {}
        if not isinstance(final, dict) or not isinstance(actual_final, dict):
            continue
        if (entry.get("expect") == "marker"
                and entry.get("marker") == required.get("marker")
                and actual_final.get("method", "GET") == final.get("method", "GET")
                and actual_final.get("path") == final.get("path")
                and actual_final.get("form") == final.get("form")):
            return list(expected_steps)
    return steps


def _reuses_confirmed_trigger(test: dict, scenarios: list[dict]) -> bool:
    """Whether a must-pass test replays a confirmed malicious trigger.

    Pass tests establish normal behavior. Replaying the confirmed marker or
    crash request cannot pass on the baseline by construction, so returning
    such a test is a test-design error rather than an oracle outcome the
    model should guess about. Sharing a benign prefix remains allowed.
    """
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            continue
        required_steps = scenario.get("steps")
        if isinstance(required_steps, list) and required_steps:
            actual_steps = test.get("steps")
            if not isinstance(actual_steps, list):
                continue
            expected = [_step_identity(step) for step in required_steps]
            actual = [_step_identity(step) for step in actual_steps]
            if (len(actual) >= len(expected)
                    and actual[:len(expected)] == expected):
                return True
        elif scenario.get("request") is not None \
                and test.get("request") == scenario.get("request"):
            return True
    return False


def validate_tests(data, *, stage: str = "generate-tests",
                   required_trigger_scenarios: list[dict] | None = None) -> list[dict]:
    """Structural validation of a model test batch. Returns sanitized tests."""
    if not isinstance(data, dict) or set(data) - {"tests", "rationale"}:
        raise RepairError("model_output_invalid",
                          "Test batch must contain exactly tests (+ optional rationale)")
    entries = data.get("tests")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TESTS:
        raise RepairError("model_output_invalid",
                          f"Between 1 and {MAX_TESTS} tests required")
    seen: set[str] = set()
    clean = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - {
                "id", "kind", "expect", "basis", "request", "response",
                "protocol", "steps", "marker"}:
            raise RepairError("model_output_invalid",
                              "Test fields: id, kind, expect, basis, request/steps, response")
        ident = entry.get("id")
        if not isinstance(ident, str) or not TEST_ID.fullmatch(ident):
            raise RepairError("model_output_invalid",
                              "Test id must match [a-z0-9_-]{1,64}")
        if ident in seen:
            raise RepairError("model_output_invalid", f"Duplicate test id: {ident}")
        seen.add(ident)
        kind = entry.get("kind")
        if kind not in TEST_KINDS:
            raise RepairError("model_output_invalid",
                              f"Test kind must be one of {list(TEST_KINDS)}")
        expect = entry.get("expect")
        if expect not in ("pass", "fatal_exit", "marker"):
            raise RepairError("model_output_invalid",
                              "expect must be pass, fatal_exit or marker")
        if kind == "regression" and expect != "pass":
            raise RepairError("model_output_invalid",
                              "regression tests must expect pass")
        if kind == "vulnerability" and expect not in ("fatal_exit", "marker"):
            raise RepairError("model_output_invalid",
                              "vulnerability tests must expect fatal_exit or marker")
        basis = entry.get("basis")
        if not isinstance(basis, str) or not 1 <= len(basis) <= 1000:
            raise RepairError("model_output_invalid",
                              "basis must be 1..1000 chars of evidence reasoning")
        request = entry.get("request")
        steps = entry.get("steps")
        protocol = entry.get("protocol", "http-ascii-get-head-port80")
        if (request is not None and steps is not None
                and ((isinstance(request, dict) and not request)
                     or steps == [])):
            # Models commonly add an empty request/steps placeholder beside
            # the other representation.  An empty placeholder carries no
            # semantics, so drop it; two non-empty representations remain
            # ambiguous and are rejected below.
            if isinstance(request, dict) and not request:
                request = None
            if steps == []:
                steps = None
        if (request is None) == (steps is None):
            raise RepairError("model_output_invalid",
                              "Test requires exactly one of request or steps")
        if request is not None and (not isinstance(request, dict)
                                    or set(request) - {"method", "path"}):
            raise RepairError("model_output_invalid",
                              "Test request needs method/path only")
        if request is not None:
            from .rehost import request_bytes
            request_bytes({"method": request.get("method", "GET"),
                           "path": request.get("path")})   # wire-safety early
            if expect == "pass":
                _reject_collapsed_framed_step(
                    request, required_trigger_scenarios or [])
        else:
            from .http_multi_step import validate_marker, validate_steps
            from .protocol import HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80
            if protocol != HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80:
                raise RepairError("model_output_invalid",
                                  "Step tests require the form/auth protocol")
            steps = _normalize_step_aliases(steps)
            steps = _canonical_confirmed_trigger(
                steps, entry, required_trigger_scenarios or [])
            if kind in {"regression", "independent"} and expect == "pass":
                steps = _inherit_confirmed_step_timing(
                    steps, required_trigger_scenarios or [])
            steps = validate_steps(steps, protocol=protocol)
            if expect == "marker":
                validate_marker(entry.get("marker"))
            elif entry.get("marker") is not None:
                raise RepairError("model_output_invalid",
                                  "Non-marker step tests cannot declare a marker")
        response = entry.get("response")
        if expect == "pass" and response is None:
            raise RepairError("model_output_invalid", "pass tests require response assertions")
        if response is not None:
            if not isinstance(response, dict) or set(response) - {"statuses", "contains"}:
                raise RepairError("model_output_invalid", "response needs statuses and optional contains")
            statuses = response.get("statuses")
            if not isinstance(statuses, list) or not statuses or len(statuses) > 20 \
                    or any(type(s) is not int or not 200 <= s <= 599 for s in statuses):
                raise RepairError("model_output_invalid", "response.statuses must list HTTP codes 200..599")
            contains = response.get("contains", "")
            if not isinstance(contains, str) or len(contains.encode("utf-8")) > 4096:
                raise RepairError("model_output_invalid", "response.contains must be <=4096 UTF-8 bytes")
            response = {"statuses": statuses, "contains": contains}
            if steps is not None and isinstance(steps, list) and steps:
                top_contains = response.get("contains", "")
                final_contains = steps[-1].get("contains", "") \
                    if isinstance(steps[-1], dict) else ""
                if top_contains and final_contains and top_contains != final_contains:
                    raise RepairError(
                        "model_output_invalid",
                        "A steps test has conflicting contains assertions: "
                        "top-level response describes only the FINAL step")
            if steps is not None:
                steps = [dict(item) for item in steps]
                final = steps[-1]
                final["statuses"] = list(dict.fromkeys(
                    [*final.get("statuses", []), *statuses]))
                final_contains = final.get("contains", "")
                top_contains = response.get("contains", "")
                if (final_contains and top_contains
                        and final_contains != top_contains):
                    raise RepairError(
                        "model_output_invalid",
                        "A steps test has conflicting contains assertions: "
                        "top-level response describes only the FINAL step, "
                        "while that step already declares different content; "
                        "keep the assertion in one place and do not copy a "
                        "prerequisite page's content to the final response")
                if top_contains:
                    final["contains"] = response["contains"]
        scenario = ({"request": {"method": request.get("method", "GET"),
                                 "path": request["path"]}}
                    if request is not None else
                    {"protocol": protocol, "steps": steps,
                     **({"marker": entry["marker"]}
                        if expect == "marker" else {})})
        clean.append({"id": ident, "kind": kind, "expect": expect,
                      "basis": basis,
                      **({"response": response} if response is not None else {}),
                      **scenario})
    missing = set(TEST_KINDS) - {t["kind"] for t in clean}
    if missing:
        raise RepairError("model_output_invalid", "Need regression, vulnerability and independent tests; missing: "
                          + ", ".join(sorted(missing)))
    vulnerability_tests = [test for test in clean
                           if test["kind"] == "vulnerability"]
    for test in clean:
        if test["kind"] in {"regression", "independent"} \
                and test["expect"] == "pass" \
                and _reuses_confirmed_trigger(
                    test, required_trigger_scenarios or []):
            raise RepairError(
                "model_output_invalid",
                f"Pass test {test['id']} reuses the confirmed malicious "
                "trigger. Regression/independent pass tests must establish "
                "normal behavior; share at most a benign prerequisite prefix "
                "and make the final request/control input valid")
    for required in required_trigger_scenarios or []:
        expected_steps = required.get("steps")
        matched = False
        for test in vulnerability_tests:
            if expected_steps is not None:
                actual = test.get("steps", [])
                expected_identity = [_step_identity(step)
                                     for step in expected_steps]
                actual_identity = [_step_identity(step) for step in actual]
                matched = (len(actual_identity) >= len(expected_identity)
                           and actual_identity[:len(expected_identity)]
                           == expected_identity)
            elif test.get("request") == required.get("request"):
                matched = True
            if matched:
                break
        if not matched:
            raise RepairError(
                "model_output_invalid",
                "A vulnerability test must replay the confirmed trigger "
                "scenario verbatim, including method, path, headers, form "
                "captures and every prerequisite step")
    return clean


def tests_prompt(reproduction: dict, checks_note: str,
                 plan: dict | None = None) -> dict:
    """Prompt for the generate-tests stage; reproduction facts only."""
    request_source = (reproduction.get("detail")
                      if isinstance(reproduction.get("detail"), list)
                      else reproduction.get("requests", []))
    requests = [{k: r.get(k) for k in ("id", "expect", "status", "request")}
                for r in request_source if isinstance(r, dict)]
    # The CONFIRMED trigger request(s): the model must reuse them verbatim
    # for vulnerability tests instead of guessing overflow lengths.
    confirmed = [r["request"] for r in requests
                 if r.get("status") == "fault_confirmed"]
    marker_mode = reproduction.get("outcome") == "command_injection_marker"
    if marker_mode:
        confirmed = [r["request"] for r in requests
                     if r.get("expect") == "marker_created"
                     and r.get("status") == "ok"]
    confirmed_scenarios = required_trigger_scenarios(reproduction, plan)
    return {
        "task": "generate_tests",
        "instruction": (
            "Write declarative HTTP tests for the rehosted firmware service. "
            "Each test is one request or one bounded multi-step scenario plus "
            "an expectation. Kinds: regression "
            "(must pass on the original), vulnerability (must trigger the "
            "confirmed fault on the original), independent (holdout, judged "
            "only in final verification). Return one JSON object: "
            '{"tests": [{"id": "unique-id", "kind": "regression|'
            'vulnerability|independent", "expect": "pass|fatal_exit|marker", '
            '"basis": "why this expectation holds", "request": {"method": '
            '"GET", "path": "/..."}, "steps": [declared multi-step requests], '
            '"protocol": "http-ascii-auth-form-multi-step-port80", "marker": "/Q", '
            '"response": {"statuses": [200], "contains": "expected content"}}], '
            '"rationale": "..."}. Include at least '
            "one regression, one vulnerability and one independent test. "
            "CRITICAL: vulnerability tests MUST preserve the confirmed trigger "
            "semantics VERBATIM. For a crash plan reuse the request; for a "
            "marker plan copy the matching object from confirmed_trigger_scenarios "
            "exactly, including ordered authenticated steps, captures, cookies, "
            "host, form fields and marker. Do not retype or guess defaults/near-miss "
            "inputs; a near-miss that does not reproduce the original fault "
            "will fail the baseline oracle. "
            "When a regression or independent test reuses a request path from "
            "a confirmed scenario, preserve that step's accept_timeout and "
            "response-framing semantics rather than turning a known framed "
            "timeout into incomplete_response. Never collapse an "
            "authenticated/framed multi-step path into one standalone request; "
            "replay the complete ordered step scenario. "
            "A regression or independent PASS test must not replay the "
            "confirmed malicious trigger as its final request; keep only a "
            "benign prerequisite prefix and make the final control input "
            "valid. "
            "For every pass expectation, response.statuses is REQUIRED and "
            "response.contains should assert meaningful expected content when known. "
            "For a steps test, response applies ONLY to the final step's HTTP "
            "response; never copy a prerequisite page's contains assertion "
            "(for example an authenticated page) to the whole scenario. Put "
            "per-step assertions on the step, and leave top-level "
            "response.contains empty unless the final response content is "
            "confirmed. A standalone request must contain method and path only. "
            "These assertions must hold on the baseline AND candidate. For fatal_exit "
            "tests response is optional and applies only to the candidate; otherwise "
            "a valid HTTP response is required after repair. Do not assume an HTTP "
            "error is a successful functional test. Paths must be ASCII "
            "printable, absolute, no whitespace or control bytes. Only output "
            "JSON."),
        "reproduction": requests,
        "confirmed_triggers": confirmed,
        "confirmed_trigger_scenarios": confirmed_scenarios,
        "fixed_checks_note": checks_note,
    }


def run_one_test(control: SessionControl, test: dict, *,
                 phase: str = "baseline", exit_timeout: float = 10.0,
                 deadline: float | None = None) -> dict:
    """Execute one test through the session channel; observe facts only.

    phase="baseline": the verdict compares against the DECLARED expectation
    (pass-kind must pass, crash-kind must produce an attributable fatal exit
    on the original firmware).
    phase="candidate": every test must SURVIVE -- pass-kind still responds,
    crash-kind no longer kills the service (the fix must hold).
    """
    if phase not in ("baseline", "candidate"):
        raise RepairError("preparation_failed", "phase must be baseline|candidate")
    if test.get("steps") is not None:
        from .http_multi_step import execute_steps, marker_scenario_passed
        runner_phase = "baseline" if phase == "baseline" else "candidate"
        execution = execute_steps(
            control, test["steps"], protocol=test["protocol"],
            phase=runner_phase,
            marker=test.get("marker") if test["expect"] == "marker" else None,
            exit_timeout=exit_timeout, deadline=deadline)
        passed = execution["passed"]
        reason = None
        if passed and test["expect"] == "marker":
            passed = marker_scenario_passed(execution, phase=runner_phase)
            if not passed:
                reason = ("marker was not created on baseline"
                          if phase == "baseline"
                          else "marker was still created on candidate")
        elif not passed:
            failed_step = next((item for item in execution["results"]
                                if item.get("status") != "ok"), None)
            reason = (failed_step or {}).get("reason") or "HTTP scenario failed"
        return {
            "id": test["id"], "kind": test["kind"],
            "expect": test["expect"], "phase": phase,
            "protocol": test["protocol"],
            "steps": [{"id": item["id"], "status": item["status"],
                       "reason": item.get("reason"),
                       "http_status": item.get("http_status"),
                       "expected_statuses": item.get("statuses"),
                       "expected_contains": item.get("contains", ""),
                       "delivery_receive": item.get("delivery", {}).get("receive")}
                      for item in execution["results"]],
            "passed": passed, "reason": reason,
            "stable_identity": execution["stable_identity"],
        }
    target = control.current_target()
    before = len(control.target_exits())
    delivery = control.deliver(test["request"])
    record = {"id": test["id"], "kind": test["kind"], "expect": test["expect"],
              "phase": phase, "request": test["request"], "delivery": {
                  k: delivery.get(k) for k in ("bytes", "sha256", "receive")}}
    need_crash = test["expect"] == "fatal_exit" and phase == "baseline"
    # A repair is accepted only after the complete observation window.  This
    # catches the common failure mode where httpd sends a 200 response and
    # faults while unwinding a moment later.
    new = _observe_exits(control, before, exit_timeout, deadline=deadline)
    if need_crash:
        if not new:
            record.update(passed=False,
                          reason="expected fatal exit, none observed")
        else:
            last = new[-1]
            attributable = (last.get("pid") == target["pid"]
                            and last.get("sha256") == target["sha256"]
                            and not last.get("intentional")
                            and last.get("signal_name") in FATAL_SIGNALS)
            record.update(passed=attributable,
                          exit_record=last,
                          reason=None if attributable else
                          "exit not attributable to the live target fault")
    else:
        response = bytes.fromhex(delivery["response_hex"])
        parsed = parse_response(response,
                                test["request"].get("method", "GET"))
        status = parsed.status if parsed is not None else _http_status(response)
        record["http_status"] = status
        if new:
            record.update(passed=False,
                          reason="service exited while survival was expected",
                          exit_record=new[-1])
        elif not delivery_complete(delivery):
            record.update(passed=False,
                          reason="HTTP response did not complete")
        elif status is None:
            record.update(passed=False, reason="no HTTP response")
        elif test.get("response") is not None and (
                status not in test["response"]["statuses"] or
                parsed is None or
                test["response"].get("contains", "").encode("utf-8")
                not in parsed.body):
            record.update(passed=False, reason="HTTP response assertion failed",
                          expected_response=test["response"])
        elif control.current_target() != target:
            record.update(passed=False, reason="target identity changed")
        else:
            record.update(passed=True, reason=None)
    return record


def _http_status(response: bytes) -> int | None:
    head = response.split(b"\r\n", 1)[0]
    match = re.match(rb"HTTP/\d\.\d (\d{3})", head)
    return int(match.group(1)) if match else None


def _probe_alive(control: SessionControl, timeout: float,
                 deadline: float | None = None) -> bool:
    """Cheap liveness probe: any well-formed HTTP response (even 404/500)
    means the service is still serving. No response with no exit record
    means hung/unresponsive -- treat as dead for restart purposes."""
    try:
        probe_timeout = _timeout_within_deadline(
            max(2.0, min(timeout, 6.0)), deadline)
        delivery = control.deliver({"method": "GET", "path": "/"},
                                   timeout=probe_timeout)
    except RepairError:
        return False
    return (delivery_complete(delivery)
            and _http_status(bytes.fromhex(
                delivery.get("response_hex") or "")) is not None)


def run_tests(control: SessionControl, tests: list[dict], logs: Path, *,
              phase: str = "baseline", exit_timeout: float = 10.0,
              restart_between: bool = False,
              baseline_sha: str | None = None,
              transaction: str | None = None,
              deadline: float | None = None) -> list[dict]:
    """Run tests in order. A dead target is restarted between tests so one
    crash does not cascade into bogus failures for later pass-tests.

    Liveness is decided by OBSERVED EXIT COUNT plus an HTTP probe, not by
    status queries: the supervisor legitimately retains a dead instance's
    identity, and a hung-but-not-crashed service (overflow-induced hang)
    produces neither an exit record nor responses. Either condition means
    the target must be restarted before the next test."""
    results = []
    exits_after_restart = len(control.target_exits())
    for test in tests:
        alive = True
        try:
            current_exits = len(control.target_exits())
        except RepairError:
            current_exits = None
            alive = False
        if current_exits is not None and current_exits > exits_after_restart:
            alive = False          # a recorded exit happened; service is dead
        if alive:
            alive = _probe_alive(control, exit_timeout, deadline)
        if not alive or restart_between:
            control.restart(transaction=transaction)
            if baseline_sha is not None:
                current = control.target_sha()
                if current != baseline_sha:
                    raise RepairError("integrity_failed",
                                      "Service restarted with different bytes; "
                                      "candidate identity changed")
            exits_after_restart = len(control.target_exits())
        results.append(run_one_test(control, test, phase=phase,
                                    exit_timeout=exit_timeout,
                                    deadline=deadline))
        save_json(logs / "test-progress.json", results)
        if not results[-1]["passed"]:
            # One failed test is already decisive in either phase.  In
            # candidate phase this also avoids trying to restart a crashed
            # candidate and misreporting its observed failure as adapter
            # infrastructure trouble.
            break
        if phase == "baseline" and "exit_record" in results[-1]:
            # A supervisor may retain the dead instance's identity. The
            # observed exit, not a status-query exception, drives restart.
            control.restart(transaction=transaction)
            if baseline_sha is not None and control.target_sha() != baseline_sha:
                raise RepairError("integrity_failed",
                                  "Baseline restart changed target bytes")
            exits_after_restart = len(control.target_exits())
    save_json(logs / "test-results.json", results)
    return results


def baseline_oracle(control: SessionControl, tests: list[dict], logs: Path, *,
                    exit_timeout: float = 10.0,
                    baseline_sha: str | None = None,
                    transaction: str | None = None,
                    deadline: float | None = None) -> list[dict]:
    """Pre-repair gate: every test must behave exactly as declared on the
    ORIGINAL firmware. A test that cannot establish its baseline is rejected
    and never becomes a judge."""
    sha = baseline_sha or control.target_sha()
    results = run_tests(control, tests, logs, exit_timeout=exit_timeout,
                        baseline_sha=sha, transaction=transaction,
                        deadline=deadline)
    failures = [{"id": r["id"], "reason": r.get("reason")}
                for r in results if not r["passed"]]
    save_json(logs / "baseline-oracle.json",
              {"baseline_sha256": sha, "failures": failures,
               "results": results})
    if failures:
        raise RepairError("baseline_oracle_failed", json.dumps(failures))
    return results


def split_holdouts(tests: list[dict]) -> tuple[list[dict], list[dict]]:
    """Independent tests are held out of every repair prompt."""
    public = [t for t in tests if t["kind"] != "independent"]
    holdout = [t for t in tests if t["kind"] == "independent"]
    return public, holdout


def verdict(results: list[dict]) -> dict:
    failed = [{"id": r["id"], "reason": r.get("reason")}
              for r in results if not r["passed"]]
    return {"passed": not failed, "failed": failed, "total": len(results),
            "ids": [r["id"] for r in results]}
