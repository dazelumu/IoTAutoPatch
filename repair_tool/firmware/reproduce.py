"""Reproduction stage: execute a validated plan through the session channel
and attribute the fault from kernel-backed exit evidence.

Order matters: control requests (expect=response) first prove the service is
alive and do not terminate it; then each confirmed trigger request must
produce exactly one new fatal exit matching the live target identity.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..config import RepairError
from ..storage import save_json
from .http_multi_step import (execute_steps, marker_scenario_passed,
                              save_progress)
from .rehost import (FATAL_SIGNALS, SessionControl, crash_evidence,
                     request_bytes)
from .protocol import (HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
                       HTTP_ASCII_GET_HEAD_PORT80)
from .tests import _http_status, _observe_exits, delivery_complete

MAX_RESPONSE_HEX = 4096  # stored per request


def _run_shape(path: str) -> tuple[str, str, str, int] | None:
    """Describe the longest homogeneous run in an ASCII request path."""
    if not isinstance(path, str) or not path:
        return None
    best_start = best_end = start = 0
    for index in range(1, len(path) + 1):
        if index < len(path) and path[index] == path[start]:
            continue
        if index - start > best_end - best_start:
            best_start, best_end = start, index
        start = index
    if best_end - best_start < 2:
        return None
    return (path[:best_start], path[best_end:], path[best_start],
            best_end - best_start)


def _compatible_run_shape(control_path: str, trigger_path: str) -> bool:
    safe = _run_shape(control_path)
    crash = _run_shape(trigger_path)
    return (safe is not None and crash is not None
            and safe[:3] == crash[:3] and safe[3] < crash[3])


def _length_probe(control: SessionControl, request: dict, baseline: dict, *,
                  exit_timeout: float, deadline: float | None) -> str:
    """Classify one length probe as fatal, safe, or inconclusive."""
    target = control.current_target()
    if target["sha256"] != baseline["sha256"]:
        raise RepairError("integrity_failed",
                          "Length differential target bytes changed")
    before = len(control.target_exits())
    delivery = control.deliver(request)
    exits = _observe_exits(control, before, exit_timeout, deadline=deadline)
    if exits:
        record = exits[-1]
        if (record.get("pid") == target["pid"]
                and record.get("sha256") == target["sha256"]
                and record.get("intentional") is not True
                and record.get("signal_name") in FATAL_SIGNALS):
            return "fatal"
        return "inconclusive"
    if delivery_complete(delivery) and _http_status(
            bytes.fromhex(delivery.get("response_hex", ""))) is not None:
        return "safe"
    return "inconclusive"


def measure_length_differential(control: SessionControl, reproduction: dict,
                                plan: dict, stage_dir: Path, *,
                                exit_timeout: float = 10.0,
                                transaction: str | None = None,
                                probe_limit: int = 8,
                                deadline: float | None = None) -> dict:
    """Bound or measure the first crashing homogeneous path-run length.

    This is a controller diagnostic, not a repair oracle.  It requires a
    model-supplied safe control and confirmed trigger with the same prefix,
    run character, and suffix.  A fatal probe restarts the baseline; a safe
    probe leaves it running.  Infrastructure and integrity failures propagate.
    """
    baseline = reproduction.get("target_start") or {}
    baseline_sha = baseline.get("sha256")
    if not isinstance(baseline_sha, str):
        return {"status": "unavailable", "reason": "missing baseline identity"}

    fault = next((item for item in reproduction.get("detail", [])
                  if item.get("status") == "fault_confirmed"), None)
    if fault is None:
        return {"status": "unavailable", "reason": "missing confirmed trigger"}
    trigger_request = fault.get("request") or {}
    trigger_shape = _run_shape(trigger_request.get("path", ""))
    if trigger_shape is None:
        return {"status": "unavailable",
                "reason": "trigger has no homogeneous run of two or more bytes"}

    safe = next((item for item in reproduction.get("detail", [])
                 if item.get("status") == "ok"
                 and item.get("expect") == "response"
                 and _compatible_run_shape(item.get("request", {}).get("path", ""),
                                           trigger_request.get("path", ""))), None)
    if safe is None:
        return {"status": "unavailable",
                "reason": "no compatible safe run-length control"}

    safe_request = safe.get("request") or {}
    safe_shape = _run_shape(safe_request.get("path", ""))
    assert safe_shape is not None
    prefix, suffix, character, high = trigger_shape
    low = safe_shape[3]
    method = trigger_request.get("method", "GET")
    if safe_request.get("method", "GET") != method:
        return {"status": "unavailable", "reason": "control method differs"}

    def restart_after_fault() -> dict:
        control.restart(transaction=transaction)
        current = control.current_target()
        if current.get("sha256") != baseline_sha:
            raise RepairError(
                "integrity_failed",
                "Length differential restart loaded different target bytes")
        return {"pid": current.get("pid"), "sha256": current.get("sha256")}

    probes: list[dict] = []
    initial_restart = restart_after_fault()
    diagnostic = {
        "status": "range_bounded",
        "method": method,
        "prefix": prefix,
        "suffix": suffix,
        "run_character": character,
        "safe_run_length": low,
        "safe_path_length": len(safe_request.get("path", "")),
        "crashing_run_length": high,
        "crashing_path_length": len(trigger_request.get("path", "")),
        "lower_bound_run_length": low,
        "upper_bound_run_length": high,
        "probe_limit": probe_limit,
        "probe_count": 0,
        "probes": probes,
        "initial_restart": initial_restart,
        "source_control_id": safe.get("id"),
        "source_trigger_id": fault.get("id"),
    }
    save_json(stage_dir / "length-differential-progress.json", diagnostic)

    while high - low > 1 and len(probes) < max(0, probe_limit):
        if deadline is not None and time.monotonic() >= deadline:
            raise RepairError("infrastructure_failed",
                              "firmware.total_timeout_seconds exceeded")
        middle = (low + high) // 2
        path = prefix + character * middle + suffix
        request = {"method": method, "path": path}
        verdict = _length_probe(control, request, baseline,
                                exit_timeout=exit_timeout, deadline=deadline)
        probe = {"run_length": middle, "path_length": len(path),
                 "request": request, "verdict": verdict}
        probes.append(probe)
        diagnostic["probe_count"] = len(probes)
        if verdict == "safe":
            low = middle
        elif verdict == "fatal":
            high = middle
            save_json(stage_dir / "length-differential-progress.json", diagnostic)
            probe["restart"] = restart_after_fault()
        else:
            diagnostic["status"] = "inconclusive"
            diagnostic["reason"] = "probe produced no attributable verdict"
            save_json(stage_dir / "length-differential-progress.json", diagnostic)
            break
        diagnostic.update({
            "lower_bound_run_length": low,
            "upper_bound_run_length": high,
        })
        save_json(stage_dir / "length-differential-progress.json", diagnostic)

    if high - low == 1:
        diagnostic["status"] = "first_crash_bounded"
        diagnostic["first_crash_run_length"] = high
        diagnostic["first_crash_path_length"] = len(
            prefix + character * high + suffix)
    else:
        diagnostic["first_crash_run_length"] = None
        diagnostic["first_crash_path_length"] = None
    save_json(stage_dir / "length-differential.json", diagnostic)
    return diagnostic


def execute_plan(control: SessionControl, plan: dict, *,
                 stage_dir: Path, exit_timeout: float = 10.0,
                 transaction: str | None = None,
                 deadline: float | None = None) -> dict:
    """Run requests in plan order; every confirmation must yield a fatal exit."""
    if plan.get("protocol") == HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80:
        if plan.get("outcome") != "command_injection_marker":
            raise RepairError("preparation_failed", "Unsupported marker plan")
        return _execute_marker_plan(control, plan, stage_dir=stage_dir,
                                    exit_timeout=exit_timeout, deadline=deadline)
    results = []
    confirmed = set()
    target0 = control.current_target()
    baseline_sha = target0["sha256"]
    baseline_exits = len(control.target_exits())
    for index, item in enumerate(plan["requests"]):
        current = control.current_target()
        if current["sha256"] != baseline_sha:
            raise RepairError("integrity_failed",
                              "Reproduction target bytes changed during plan "
                              "execution")
        request = {"method": item.get("method", "GET"), "path": item["path"]}
        expect = item.get("expect", "response")
        if expect == "response":
            exits_before = len(control.target_exits())
            delivery = control.deliver(request)
            new_exits = _observe_exits(control, exits_before, exit_timeout,
                                       deadline=deadline)
            record = {"id": item["id"], "expect": expect, "request": request,
                      "delivery": delivery, "status": "ok", "exits": new_exits}
            if new_exits:
                record["status"] = "control_killed_service"
                results.append(record)
                break
            if not delivery_complete(delivery):
                record["status"] = "control_incomplete_response"
                results.append(record)
                break
            if _http_status(bytes.fromhex(delivery["response_hex"])) is None:
                record["status"] = "control_no_response"
                results.append(record)
                break
        else:
            trigger_target = control.current_target()
            if trigger_target["sha256"] != baseline_sha:
                raise RepairError("integrity_failed",
                                  "Trigger target bytes differ from the "
                                  "reproduction baseline")
            evidence = crash_evidence(control, request,
                                      exit_timeout=exit_timeout,
                                      deadline=deadline)
            confirmed.add(item["id"])
            record = {"id": item["id"], "expect": expect, "request": request,
                      "delivery": evidence["delivery"],
                      "observation": evidence["observation"],
                      "exit_record": evidence["exit_record"],
                      "status": "fault_confirmed"}
        results.append(record)
        save_json(stage_dir / "reproduction-progress.json",
                  {"results": results})
        if record["status"] == "fault_confirmed" \
                and index + 1 < len(plan["requests"]):
            control.restart(transaction=transaction)
            restarted = control.current_target()
            if restarted["sha256"] != baseline_sha:
                raise RepairError(
                    "integrity_failed",
                    "Baseline restart after a confirmed fault loaded "
                    "different target bytes")
            record["baseline_restart"] = {
                "sha256": restarted["sha256"], "pid": restarted["pid"]}
            save_json(stage_dir / "reproduction-progress.json",
                      {"results": results})
    missing = [c for c in plan["confirmations"] if c not in confirmed]
    broken_controls = [r for r in results if r["status"] != "ok"
                       and r["expect"] == "response"]
    target_end: dict | None
    last = results[-1] if results else None
    if last and last.get("status") == "fault_confirmed" \
            and "baseline_restart" not in last:
        exit_record = last.get("exit_record") or {}
        target_end = {
            "state": "exited",
            "pid": exit_record.get("pid"),
            "sha256": exit_record.get("sha256"),
            "signal": exit_record.get("signal_name"),
        }
    else:
        try:
            target_end = control.current_target()
        except RepairError:
            target_end = {"state": "unavailable"}
    reproduction = {
        "confirmed": not missing and not broken_controls,
        "confirmations": plan["confirmations"],
        "confirmed_ids": sorted(confirmed),
        "missing": missing,
        "control_failures": [r["id"] for r in broken_controls],
        "requests": [{k: r.get(k) for k in ("id", "expect", "status", "request")}
                     for r in results],
        "detail": [{**r, "delivery": {k: r["delivery"].get(k) for k in
                                      ("receive", "bytes", "sha256")}}
                   for r in results],
        "target_start": target0,
        "target_end": target_end,
        "baseline_exits": baseline_exits,
    }
    save_json(stage_dir / "reproduction.json", reproduction)
    return reproduction


def _execute_marker_plan(control: SessionControl, plan: dict, *,
                         stage_dir: Path, exit_timeout: float,
                         deadline: float | None) -> dict:
    """Run a command-injection differential and judge its marker evidence."""
    execution = execute_steps(
        control, plan["requests"],
        protocol=HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
        phase="baseline", marker=plan["marker"],
        exit_timeout=exit_timeout, deadline=deadline)
    confirmed_ids = [
        item["id"] for item in execution["results"]
        if item.get("status") == "ok"
        and item.get("expect") == "marker_created"
        and item.get("marker_after", {}).get("exists")
        and item.get("marker_after", {}).get("empty")
    ]
    missing = [item for item in plan["confirmations"]
               if item not in confirmed_ids]
    control_failures = [
        item["id"] for item in execution["results"]
        if item.get("status") != "ok"
        and item.get("expect") in {"response", "marker_absent"}
    ]
    broken_triggers = [
        item["id"] for item in execution["results"]
        if item.get("expect") == "marker_created" and item.get("status") != "ok"
    ]

    reproduction = {
        "confirmed": (execution["passed"] and marker_scenario_passed(
            execution, phase="baseline") and not missing),
        "outcome": plan["outcome"],
        "protocol": plan["protocol"],
        "marker": plan["marker"],
        "confirmations": plan["confirmations"],
        "confirmed_ids": confirmed_ids,
        "missing": missing,
        "control_failures": control_failures,
        "trigger_failures": broken_triggers,
        "requests": [{**{key: item.get(key)
                         for key in ("id", "expect", "status")},
                      "request": _marker_request_view(item)}
                     for item in execution["results"]],
        "detail": execution["results"],
        "target_start": execution["target_start"],
        "target_end": execution["target_end"],
        "stable_identity": execution["stable_identity"],
    }
    save_json(stage_dir / "reproduction.json", reproduction)
    save_progress(stage_dir / "reproduction-progress.json", execution)
    return reproduction


def _marker_request_view(item: dict) -> dict:
    """Model-safe view: captured cookie values remain local evidence only."""
    return {key: item[key] for key in
            ("method", "path", "form", "referer", "capture_cookies",
             "capture_fields") if key in item}


def reproduce_and_report(control: SessionControl, plan: dict, stage_dir: Path,
                         *, exit_timeout: float = 10.0,
                         transaction: str | None = None,
                         deadline: float | None = None,
                         length_differential: bool = False,
                         length_probe_limit: int = 8) -> dict:
    """Execute the plan; on success keep one canonical fault summary for later
    stages. The service is left running (post-fault restart is the adapter's
    job during repair deployment, not here)."""
    reproduction = execute_plan(control, plan, stage_dir=stage_dir,
                                exit_timeout=exit_timeout,
                                transaction=transaction, deadline=deadline)
    if not reproduction["confirmed"]:
        reasons = []
        if reproduction["missing"] and reproduction.get("outcome") == "command_injection_marker":
            reasons.append(f"confirmed triggers did not create the declared marker: "
                           f"{reproduction['missing']}")
        elif reproduction["missing"]:
            reasons.append(f"confirmed triggers did not produce attributable "
                           f"fatal exits: {reproduction['missing']}")
        if reproduction["control_failures"]:
            reasons.append(f"control requests terminated the service: "
                           f"{reproduction['control_failures']}")
        raise RepairError("reproduction_failed", "; ".join(reasons))
    if reproduction.get("outcome") == "command_injection_marker":
        trigger = next(item for item in reproduction["detail"]
                       if item.get("id") in reproduction["confirmed_ids"])
        summary = {
            "request": _marker_request_view(trigger),
            "marker": {
                "guest_path": reproduction["marker"],
                "created": True,
                "empty": True,
            },
            "outcome": "command_injection_marker",
            "protocol": reproduction["protocol"],
        }
        save_json(stage_dir / "fault-summary.json", summary)
        return reproduction
    fault = next(r for r in reproduction["detail"]
                 if r["status"] == "fault_confirmed")
    summary = {
        "request": {"method": "GET", "path": None},
        "signal": fault["observation"]["signal"],
        "exit_record": fault["exit_record"],
        "debug_context": fault["observation"].get("debug_context"),
    }
    for item in plan["requests"]:
        if item["id"] == fault["id"]:
            summary["request"] = {"method": item.get("method", "GET"),
                                  "path": item["path"]}
    if length_differential:
        summary["length_differential"] = measure_length_differential(
            control, reproduction, plan, stage_dir,
            exit_timeout=exit_timeout, transaction=transaction,
            probe_limit=length_probe_limit, deadline=deadline)
        reproduction["length_differential"] = summary["length_differential"]
        save_json(stage_dir / "reproduction.json", reproduction)
    save_json(stage_dir / "fault-summary.json", summary)
    return reproduction
