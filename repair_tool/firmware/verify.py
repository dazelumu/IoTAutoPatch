"""Verification: fixed functional checks, plan replay, redeploy re-check.

The verifier is independent of repair generation: it consumes the session,
the reproduction plan, the candidate bytes and the operator's fixed checks,
and judges from observations only.

1. fixed_checks  - operator-configured HTTP checks (never model-generated);
                   must pass on the ORIGINAL baseline before any repair and
                   on the candidate after deployment.
2. replay_plan   - the reproduction plan is replayed against the repaired
                   service: trigger requests must NOT produce new fatal exits
                   and the target identity (pid/sha256) must stay stable.
3. redeploy      - after acceptance the baseline is restored, then the
                   candidate redeployed in the SAME session; checks and
                   replay must pass again (proves the patch is reproducible,
                   not a leftover of a lucky session state).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..config import RepairError
from ..storage import save_json, sha
from .http import parse_response
from .http_multi_step import execute_steps, marker_scenario_passed
from .protocol import (HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
                       HTTP_ASCII_GET_HEAD_PORT80)
from .rehost import SessionControl, firmware_deadline_exceeded, restore
from .reproduce import reproduce_and_report
from .tests import (_http_status, _observe_exits, delivery_complete, run_tests,
                    verdict)

REDEPLOY_WAIT = 1.0


def run_fixed_checks(control: SessionControl, checks: list[dict], logs: Path, *,
                     exit_timeout: float = 1.0,
                     deadline: float | None = None) -> dict:
    """Operator checks: request -> expected statuses (+optional contains)."""
    results = []
    for index, check in enumerate(checks):
        protocol = check.get("protocol", HTTP_ASCII_GET_HEAD_PORT80)
        if "steps" in check:
            steps = [dict(item) for item in check["steps"]]
            if steps:
                final = steps[-1]
                if check.get("statuses") and not final.get("statuses"):
                    final["statuses"] = check["statuses"]
                if check.get("contains") and not final.get("contains"):
                    final["contains"] = check["contains"]
            execution = execute_steps(
                control, steps, protocol=protocol, phase="fixed",
                exit_timeout=exit_timeout, deadline=deadline)
            last = execution["results"][-1] if execution["results"] else {}
            response_status = last.get("http_status")
            # Per-step assertions have already run.  The outer check provides
            # the operator's final-response acceptance contract.
            record = {"protocol": protocol, "steps": [
                      {key: item.get(key) for key in
                       ("id", "status", "reason", "http_status")}
                      for item in execution["results"]],
                      "http_status": response_status,
                      "receive": last.get("delivery", {}).get("receive")}
            complete = execution["passed"]
            contains = check.get("contains", "")
            ok_status = response_status in check.get("statuses", [])
            record.update(passed=bool(complete and ok_status),
                          expected_statuses=check.get("statuses"),
                          contains=contains or None,
                          response_complete=complete)
            results.append(record)
            save_json(logs / "fixed-checks-progress.json", results)
            if not record["passed"]:
                break
            continue
        request = check["request"]
        target = control.current_target()
        exits_before = len(control.target_exits())
        if protocol == HTTP_ASCII_GET_HEAD_PORT80:
            delivery = control.deliver(request)
        else:
            delivery = control.deliver(request, protocol=protocol)
        new_exits = _observe_exits(control, exits_before, exit_timeout,
                                   deadline=deadline)
        response = bytes.fromhex(delivery["response_hex"])
        parsed = parse_response(response, request.get("method", "GET"))
        status = parsed.status if parsed is not None else _http_status(response)
        record = {"protocol": protocol, "request": request,
                  "http_status": status,
                  "receive": delivery["receive"]}
        ok_status = status in check.get("statuses", [])
        contains = check.get("contains", "")
        ok_contains = (not contains or
                       (parsed is not None and
                        contains.encode("utf-8") in parsed.body))
        complete = delivery_complete(delivery) and parsed is not None
        # A new exit already proves this check failed.  Do not query identity
        # after that point: a dead target would turn a functional verdict into
        # an infrastructure error before this function can classify it.
        stable = (control.current_target() == target) if not new_exits else False
        record.update(passed=bool(complete and stable and ok_status and ok_contains),
                      expected_statuses=check.get("statuses"),
                      contains=contains or None,
                      response_complete=complete,
                      exits=new_exits)
        results.append(record)
        save_json(logs / "fixed-checks-progress.json", results)
        if not record["passed"]:
            break
    save_json(logs / "fixed-checks.json", results)
    failed = [r for r in results if not r["passed"]]
    if failed:
        raise RepairError("functional_failed",
                          f"Fixed functional checks failed: {failed}")
    return {"passed": True, "checks": len(checks)}


def replay_plan(control: SessionControl, plan: dict, logs: Path, *,
                exit_timeout: float = 10.0,
                transaction: str | None = None,
                deadline: float | None = None) -> dict:
    """Post-repair replay of the reproduction plan.

    Success = every control request still gets a response, no request
    produces a NEW fatal exit, and the target identity is unchanged after
    the replay. This is the mirror of the reproduction gate: what crashed
    before must now survive."""
    target0 = control.current_target()
    if plan.get("protocol") == HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80:
        if plan.get("outcome") != "command_injection_marker":
            raise RepairError("preparation_failed", "Unsupported marker replay")
        execution = execute_steps(
            control, plan["requests"],
            protocol=HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
            phase="candidate", marker=plan["marker"],
            exit_timeout=exit_timeout, deadline=deadline)
        bad = [{"id": item["id"], "status": item["status"],
                "reason": item.get("reason")}
               for item in execution["results"] if item["status"] != "ok"]
        replay = {
            "stable_identity": execution["stable_identity"],
            "identity_confirmed": execution["stable_identity"],
            "outcome": plan["outcome"],
            "marker": plan["marker"],
            "results": execution["results"],
            "violations": bad,
        }
        save_json(logs / "replay.json", replay)
        if bad or not execution["passed"] \
                or not marker_scenario_passed(execution, phase="candidate"):
            reasons = [
                f"{item['id']}: {item['reason'] or item['status']}"
                for item in bad
            ]
            if not execution["passed"] and not reasons:
                reasons.append("marker replay did not complete")
            raise RepairError("verification_failed", "; ".join(reasons))
        return replay
    results = []
    for item in plan["requests"]:
        # A candidate that crashed on an earlier request leaves the service
        # dead; restart it (same bytes, same transaction) so later control
        # requests report real behaviour instead of cascading no_response.
        if results and results[-1]["status"] == "new_fatal_exit":
            try:
                control.restart(transaction=transaction)
            except RepairError as exc:
                if firmware_deadline_exceeded(exc):
                    raise
                # The observed crash is already a candidate verdict.  A failed
                # recovery restart must not disguise that verdict as adapter
                # infrastructure failure.
                replay = {
                    "stable_identity": False,
                    "identity_confirmed": False,
                    "results": results,
                    "violations": [{"id": item["id"], "status": item["status"]}
                                   for item in results if item["status"] != "ok"],
                }
                save_json(logs / "replay.json", replay)
                raise RepairError(
                    "verification_failed",
                    f"{results[-1]['id']}: new_fatal_exit; later requests "
                    "were not replayed because the candidate could not restart"
                ) from exc
            if control.target_sha() != target0["sha256"]:
                raise RepairError(
                    "integrity_failed",
                    "Replay restart loaded bytes different from the candidate")
        request = {"method": item.get("method", "GET"), "path": item["path"]}
        exits_before = len(control.target_exits())
        delivery = control.deliver(request)
        # Every candidate request gets the full observation window.  A
        # response followed by a delayed fatal exit is still a failed repair.
        new_exits = _observe_exits(control, exits_before, exit_timeout,
                                   deadline=deadline)
        record = {"id": item["id"], "delivery": {
            k: delivery.get(k) for k in ("bytes", "sha256", "receive")}}
        if new_exits:
            record.update(status="new_fatal_exit", exits=new_exits)
        elif not delivery_complete(delivery):
            record.update(status="incomplete_response")
        elif _http_status(bytes.fromhex(delivery["response_hex"])) is None:
            record.update(status="no_response")
        else:
            record.update(status="ok")
        results.append(record)
        save_json(logs / "replay-progress.json", results)
    bad = [r for r in results if r["status"] != "ok"]
    if bad:
        # The behavioural violation is already decisive.  The final request may
        # have killed the target; asking for a live identity must not promote
        # that candidate failure to an infrastructure failure.
        stable = False
    else:
        identity = control.current_target()
        # Candidate-phase stability is about BYTES, not the live pid: a
        # restart after an observed crash legitimately changes the pid, and
        # the loop's own restarts do too. What must never change is which
        # binary runs.
        stable = identity["sha256"] == target0["sha256"]
    replay = {"stable_identity": stable, "results": results,
              "violations": [{"id": r["id"], "status": r["status"]} for r in bad]}
    save_json(logs / "replay.json", replay)
    if bad or not stable:
        reasons = [f"{r['id']}: {r['status']}" for r in bad]
        if not stable and not bad:
            reasons.append("target identity changed during replay")
        raise RepairError("verification_failed", "; ".join(reasons) or "replay failed")
    return replay


def verify_candidate(control: SessionControl, *, checks: list[dict],
                     plan: dict, tests: list[dict], logs: Path,
                     exit_timeout: float = 10.0,
                     transaction: str | None = None,
                     deadline: float | None = None) -> dict:
    """Full verification of a DEPLOYED candidate (already replaced+restarted):
    fixed checks, plan replay and the model-generated test set. Tests run in
    candidate phase: every one must survive (crash tests must no longer kill
    the service)."""
    candidate_sha = control.target_sha()
    fixed = run_fixed_checks(control, checks, logs,
                             exit_timeout=exit_timeout, deadline=deadline)
    replay = replay_plan(control, plan, logs, exit_timeout=exit_timeout,
                         transaction=transaction, deadline=deadline)
    results = run_tests(control, tests, logs / "tests", phase="candidate",
                        exit_timeout=exit_timeout, baseline_sha=candidate_sha,
                        transaction=transaction, deadline=deadline)
    outcome = verdict(results)
    save_json(logs / "candidate-verification.json",
              {"fixed": fixed, "replay": {"stable_identity": replay["stable_identity"]},
               "tests": outcome})
    if not outcome["passed"]:
        holdout_ids = {t["id"] for t in tests if t["kind"] == "independent"}
        if any(item["id"] in holdout_ids for item in outcome["failed"]):
            # Detailed results remain local; this status is terminal and
            # must never become feedback to the repair model.
            raise RepairError("independent_rejected",
                              "Independent firmware evaluation rejected the candidate")
        raise RepairError("verification_failed",
                          f"Generated tests failed: {outcome['failed']}")
    return {"fixed": fixed, "replay": replay, "tests": outcome}


def redeploy_and_verify(control: SessionControl, *, baseline: Path,
                        candidate: Path, checks: list[dict], plan: dict,
                        tests: list[dict], logs: Path, target_rel: str,
                        transaction: str | None = None,
                        exit_timeout: float = 10.0,
                        deadline: float | None = None) -> dict:
    """Acceptance-grade re-verification: roll back to the baseline bytes,
    re-verify the baseline still works (and the fault is still gone only
    after redeploying the candidate), then redeploy the candidate and run
    the full verification once more in the same session."""
    logs.mkdir(parents=True, exist_ok=True)
    # 1. Roll back to baseline bytes; service must work again.
    restore(control, baseline, target_rel, transaction=transaction)
    try:
        rollback_checks = run_fixed_checks(
            control, checks, logs / "rollback", exit_timeout=exit_timeout,
            deadline=deadline)
    except RepairError as exc:
        # The candidate already passed this gate. A degraded restored
        # baseline is session/environment failure, not repair feedback.
        raise RepairError(
            "infrastructure_failed",
            "Restored baseline failed final fixed checks") from exc
    # Re-establish the causal baseline in the fresh verification session.
    # A changed rootfs/config can otherwise make the old trigger disappear and
    # let an unrelated candidate look successful.
    try:
        baseline_reproduction = reproduce_and_report(
            control, plan, logs / "rollback" / "reproduction",
            exit_timeout=exit_timeout, transaction=transaction,
            deadline=deadline)
    except RepairError as exc:
        raise RepairError(
            "infrastructure_failed",
            "Restored baseline no longer reproduces the confirmed fault") from exc
    control.restart(transaction=transaction)
    if control.target_sha() != sha(baseline):
        raise RepairError(
            "integrity_failed",
            "Baseline restart after fault reproduction changed target bytes")
    save_json(logs / "rollback" / "rollback.json",
              {"restored_sha256": sha(baseline), "checks": rollback_checks,
               "reproduction_confirmed": baseline_reproduction["confirmed"]})
    # 2. Redeploy the candidate; verification must pass again.
    redeploy_wait = REDEPLOY_WAIT
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RepairError("infrastructure_failed",
                              "firmware.total_timeout_seconds exceeded")
        redeploy_wait = min(redeploy_wait, remaining)
    time.sleep(redeploy_wait)
    control.replace_target(candidate, transaction=transaction)
    deployed_sha = control.target_sha()
    if deployed_sha != sha(candidate):
        raise RepairError("integrity_failed",
                          "Redeployed target sha does not match the candidate")
    verification = verify_candidate(control, checks=checks, plan=plan,
                                    tests=tests, logs=logs / "redeploy",
                                    exit_timeout=exit_timeout,
                                    transaction=transaction, deadline=deadline)
    save_json(logs / "redeploy.json",
              {"candidate_sha256": sha(candidate), "baseline_sha256": sha(baseline),
               **verification})
    return verification
