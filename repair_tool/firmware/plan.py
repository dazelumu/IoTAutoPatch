"""PoC analysis contract: model reads the PoC source and emits a declarative
reproduction plan. The software executes the plan; the model never produces
executable code here.

Plan schema (model output, one JSON object):
  analysis       - short natural-language explanation of the triggering input
  requests       - ordered declarative requests, validated by a protocol driver
  confirmations  - ids that must cause a fatal exit or a declared marker effect

Every request id referenced in confirmations must exist. Paths carry the
concrete bytes; the tool is the only side that talks to the session.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..config import RepairError
from .http_multi_step import validate_marker, validate_steps
from .protocol import (HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
                       HTTP_ASCII_GET_HEAD_PORT80, protocol_driver)

PLAN_KEYS = {"analysis", "requests", "confirmations", "confirmation",
             "protocol", "outcome", "marker"}
NEW_STEP_KEYS = {
    "id", "method", "path", "host", "port", "referer", "form",
    "content_type", "capture_cookies", "capture_fields", "expect",
    "statuses", "contains", "accept_timeout",
}
MAX_REQUESTS = 30
MAX_ANALYSIS_CHARS = 4000


def plan_prompt(poc_source: str, transport_note: str) -> dict:
    """User payload for the poc-analysis stage. No device facts, no fixes."""
    return {
        "task": "poc_analysis",
        "instruction": (
            "Analyze the PoC script below. It targets a rehosted firmware web "
            "service reachable through this software's session channel. Decide "
            "how to reproduce the fault using ONLY declarative HTTP requests. "
            "If the PoC defines build_plan() or otherwise contains a complete "
            "declarative reproduction plan, that plan is authoritative: return "
            "its request objects field-for-field, preserving every step, id, "
            "path, host, referer, form field, capture declaration, marker, "
            "confirmation, and accept_timeout setting. Do not replace a "
            "declared command-injection objective with a crash hypothesis. "
            "When feedback shows stable_identity=true and no target exit, a "
            "timeout is not a fatal exit; preserve the PoC's explicit "
            "accept_timeout=true on a known slow page. "
            "For a crash, return {\"analysis\": string, \"requests\": "
            "[{\"id\": string, \"method\": \"GET\"|\"HEAD\", \"path\": string, "
            "\"expect\": \"response\"|\"fatal_exit\"}], \"confirmations\": [ids]}. "
            "Paths must be concrete (include exact repeated bytes, lengths, "
            "extensions as needed), ASCII printable, no whitespace or control "
            "characters. A request with expect=fatal_exit must plausibly "
            "trigger abnormal termination of the target service process; "
            "expect=response requests are controls that must NOT terminate it. "
            "If the suspected trigger varies a repeated byte run, include one "
            "same-method control with the same prefix and suffix but a "
            "shorter run. "
            "For a command-injection side effect, set protocol to "
            "\"http-ascii-auth-form-multi-step-port80\", outcome to "
            "\"command_injection_marker\", and return this exact object shape: "
            "{\"analysis\": string, \"protocol\": "
            "\"http-ascii-auth-form-multi-step-port80\", \"outcome\": "
            "\"command_injection_marker\", \"marker\": \"/absolute/path\", "
            "\"requests\": [step objects], \"confirmations\": [ids]}. The "
            "top-level key is named marker, never marker_path or marker_path_"
            "guest. The list is named requests, never steps. A POST body is "
            "named form, never fields. capture_cookies is boolean, never a "
            "list; omit it unless the PoC establishes that a cookie is really "
            "set. POST form values may be literals or {\"capture\": name}; "
            "only earlier explicitly declared capture_fields and "
            "capture_cookies may be replayed. "
            "expect is response, marker_absent, or marker_created. Include a "
            "pre-trigger control, the exact trigger, and a post-trigger "
            "control; confirmations must reference marker_created trigger ids. "
            "Only for a known slow/streaming page, a step may set "
            "accept_timeout=true with explicit statuses and contains; the "
            "declared content must still be observed. "
            "Do not include code, shell commands or scripts. Only output JSON."),
        "poc_source": poc_source,
        "service_channel": transport_note,
    }


def validate_plan(plan) -> dict:
    """Structural validation; wire-level safety is enforced by request_bytes()."""
    if not isinstance(plan, dict):
        raise RepairError("model_output_invalid", "Plan must be an object")
    protocol = plan.get("protocol", HTTP_ASCII_GET_HEAD_PORT80)
    outcome = plan.get("outcome")
    marker = plan.get("marker")
    if protocol == HTTP_ASCII_GET_HEAD_PORT80:
        if outcome is not None or marker is not None:
            raise RepairError("model_output_invalid",
                              "GET/HEAD plans do not support side-effect fields")
        return _validate_crash_plan(plan)
    if protocol != HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80:
        raise RepairError("model_output_invalid", "Unsupported reproduction protocol")
    if outcome != "command_injection_marker":
        raise RepairError("model_output_invalid", "Unsupported reproduction outcome")
    return _validate_marker_plan(plan, protocol)


def _validate_crash_plan(plan: dict) -> dict:
    allowed = {"protocol", "analysis", "requests", "confirmations", "confirmation"}
    if set(plan) - allowed:
        raise RepairError("model_output_invalid",
                          f"Unknown plan fields: {sorted(set(plan) - allowed)}")
    analysis = plan.get("analysis")
    if not isinstance(analysis, str) or not analysis.strip():
        raise RepairError("model_output_invalid", "Plan requires an analysis string")
    if len(analysis) > MAX_ANALYSIS_CHARS:
        raise RepairError("model_output_invalid", "analysis too long")
    requests = plan.get("requests")
    if not isinstance(requests, list) or not 1 <= len(requests) <= MAX_REQUESTS:
        raise RepairError("model_output_invalid",
                          f"Plan requires 1..{MAX_REQUESTS} requests")
    ids = set()
    for item in requests:
        if not isinstance(item, dict) or set(item) - {"id", "method", "path", "expect"}:
            raise RepairError("model_output_invalid", "Invalid request entry")
        rid = item.get("id")
        if not isinstance(rid, str) or not re.fullmatch(r"[a-z0-9_-]{1,32}", rid):
            raise RepairError("model_output_invalid", "Request id must be [a-z0-9_-]{1,32}")
        if rid in ids:
            raise RepairError("model_output_invalid", f"Duplicate request id: {rid}")
        ids.add(rid)
        protocol_driver(HTTP_ASCII_GET_HEAD_PORT80).validate_request(
            {"method": item.get("method", "GET"), "path": item.get("path")})
        if item.get("expect") not in {"response", "fatal_exit"}:
            raise RepairError("model_output_invalid", "expect must be response or fatal_exit")
    confirmations = plan.get("confirmations")
    if confirmations is None and "confirmation" in plan:
        confirmations = [plan["confirmation"]]
    if not isinstance(confirmations, list) or not confirmations or \
            not all(isinstance(c, str) for c in confirmations):
        raise RepairError("model_output_invalid", "confirmations must be a nonempty id list")
    unknown = [c for c in confirmations if c not in ids]
    if unknown:
        raise RepairError("model_output_invalid",
                          f"confirmations reference unknown ids: {unknown}")
    request_expectations = {item["id"]: item.get("expect", "response")
                            for item in requests}
    non_fatal = [c for c in confirmations
                 if request_expectations[c] != "fatal_exit"]
    if non_fatal:
        raise RepairError("model_output_invalid",
                          "confirmations may reference only requests with "
                          f"expect=fatal_exit: {non_fatal}")
    return {"analysis": analysis, "requests": requests,
            "confirmations": confirmations}


def _validate_marker_plan(plan: dict, protocol: str) -> dict:
    if set(plan) - PLAN_KEYS:
        raise RepairError("model_output_invalid",
                          f"Unknown plan fields: {sorted(set(plan) - PLAN_KEYS)}")
    analysis = plan.get("analysis")
    if not isinstance(analysis, str) or not analysis.strip() \
            or len(analysis) > MAX_ANALYSIS_CHARS:
        raise RepairError("model_output_invalid",
                          "Plan requires an analysis string up to 4000 chars")
    requests = plan.get("requests")
    if not isinstance(requests, list) or not 1 <= len(requests) <= MAX_REQUESTS:
        raise RepairError("model_output_invalid",
                          f"Plan requires 1..{MAX_REQUESTS} requests")
    for item in requests:
        if not isinstance(item, dict) or set(item) - NEW_STEP_KEYS:
            raise RepairError("model_output_invalid",
                              "Invalid multi-step request entry")
    marker = validate_marker(plan.get("marker"))
    clean_steps = validate_steps(requests, protocol=protocol)
    ids = [item["id"] for item in clean_steps]
    confirmations = plan.get("confirmations")
    if confirmations is None and "confirmation" in plan:
        confirmations = [plan["confirmation"]]
    if (not isinstance(confirmations, list) or not confirmations
            or not all(isinstance(item, str) for item in confirmations)):
        raise RepairError("model_output_invalid",
                          "confirmations must be a nonempty id list")
    unknown = [item for item in confirmations if item not in ids]
    if unknown:
        raise RepairError("model_output_invalid",
                          f"confirmations reference unknown ids: {unknown}")
    expectations = {item["id"]: item.get("expect", "response")
                    for item in clean_steps}
    invalid = [item for item in confirmations
               if expectations[item] != "marker_created"]
    if invalid:
        raise RepairError("model_output_invalid",
                          "Marker confirmations must reference marker_created steps: "
                          f"{invalid}")
    marker_steps = [item for item in clean_steps
                    if item.get("expect") in {"marker_created", "marker_absent"}]
    if not marker_steps:
        raise RepairError("model_output_invalid",
                          "Marker plans require marker expectations")
    return {
        "analysis": analysis,
        "protocol": protocol,
        "outcome": "command_injection_marker",
        "marker": marker,
        "requests": clean_steps,
        "confirmations": confirmations,
    }


def load_plan(path: Path) -> dict:
    return validate_plan(json.loads(Path(path).read_text(encoding="utf-8")))


def transport_note() -> str:
    return ("HTTP/1.1 requests are delivered verbatim through the session's "
            "private Unix-socket tunnel to the rehosted service (default HTTP "
            "port). Registered protocols are ASCII GET/HEAD and bounded ASCII "
            "GET/HEAD/POST form-plus-cookie multi-step HTTP. Responses are "
            "observed as raw bytes; abnormal termination "
            "of the target process is observed from kernel-backed exit "
            "records bound to the registered instance pid/sha256.")
