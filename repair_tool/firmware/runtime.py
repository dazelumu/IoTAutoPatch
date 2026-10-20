"""Firmware runtime capability registry.

Capabilities are factual boundaries, not aspirations.  In particular, FirmAE
and Greenhouse start as diagnostic-only backends and cannot replace the current
DIR-825 authoritative verification runtime without the full transaction and
rollback proof described in the design document.
"""
from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType

from ..arch.names import MIPS32BE, architecture_names
from ..config import RepairError
from .protocol import (HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
                       HTTP_ASCII_GET_HEAD_PORT80, protocol_names)


RUNTIME_CAPABILITY_SCHEMA = "runtime-capability-v1"


NATIVE_PROOT_MIPS32BE = {
    "schema": RUNTIME_CAPABILITY_SCHEMA,
    "runtime": "native-proot-mips32be",
    "capabilities": {
        "boot": True,
        "deliver_http_get_head": True,
        "deliver_http_body": True,
        "deliver_http_form_post": True,
        "multi_step_http": True,
        "cookie_session": True,
        "side_effect_marker": True,
        "deliver_raw_tcp": False,
        "replay": True,
        "replace_target": True,
        "rollback": True,
        "target_identity": True,
        "fault_context": True,
        "transactional_mutation": True,
        "authoritative_verification": True,
    },
    "supported_architectures": [MIPS32BE],
    "supported_protocols": [HTTP_ASCII_GET_HEAD_PORT80,
                            HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80],
    "limits": {
        "http_port": 80,
        "request_ascii_only": True,
        "request_body": "form-urlencoded",
        "max_form_fields": 32,
        "max_form_body_bytes": 16384,
        "marker_kinds": ["empty_file"],
    },
}

FIRMAE = {
    "schema": RUNTIME_CAPABILITY_SCHEMA,
    "runtime": "firmae",
    "capabilities": {
        "boot": True,
        "triage": True,
        "diagnostics": True,
        "service_discovery": True,
        "deliver_http_get_head": False,
        "deliver_http_body": False,
        "deliver_raw_tcp": False,
        "replay": False,
        "replace_target": False,
        "rollback": False,
        "target_identity": False,
        "fault_context": False,
        "transactional_mutation": False,
        "authoritative_verification": False,
    },
    "supported_architectures": [],
    "supported_protocols": [],
    "limits": {
        "diagnostic_only": True,
        "authoritative_verification": False,
    },
}

GREENHOUSE = {
    "schema": RUNTIME_CAPABILITY_SCHEMA,
    "runtime": "greenhouse",
    "capabilities": {
        "boot": False,
        "triage": True,
        "diagnostics": True,
        "single_service_rehost": True,
        "replay": True,
        "fuzz": True,
        "deliver_http_get_head": False,
        "deliver_http_body": False,
        "deliver_raw_tcp": False,
        "replace_target": False,
        "rollback": False,
        "target_identity": False,
        "fault_context": True,
        "transactional_mutation": False,
        "authoritative_verification": False,
    },
    "supported_architectures": [],
    "supported_protocols": [],
    "limits": {
        "diagnostic_only": True,
        "authoritative_verification": False,
    },
}



_RUNTIME_DEFINITIONS = {
    NATIVE_PROOT_MIPS32BE["runtime"]: NATIVE_PROOT_MIPS32BE,
    FIRMAE["runtime"]: FIRMAE,
    GREENHOUSE["runtime"]: GREENHOUSE,
}


def _protocol_bindings() -> dict[str, tuple[str, ...]]:
    """Bind every runtime protocol declaration to a registered driver."""
    registered = protocol_names()
    bindings: dict[str, tuple[str, ...]] = {}
    for runtime, report in _RUNTIME_DEFINITIONS.items():
        protocols = report.get("supported_protocols")
        if not isinstance(protocols, list) or not all(
                isinstance(protocol, str) for protocol in protocols):
            raise RepairError(
                "preparation_failed",
                f"Runtime {runtime!r} has malformed supported_protocols")
        missing = tuple(protocol for protocol in protocols
                        if protocol not in registered)
        if missing:
            raise RepairError(
                "protocol_unsupported",
                f"Runtime {runtime!r} declares unregistered protocols: "
                f"{list(missing)}; registered protocols: {list(registered)}")
        bindings[runtime] = tuple(protocols)
    return bindings


def _architecture_bindings() -> dict[str, tuple[str, ...]]:
    """Bind runtime architecture declarations to the closed W6 registry."""
    registered = architecture_names()
    bindings: dict[str, tuple[str, ...]] = {}
    for runtime, report in _RUNTIME_DEFINITIONS.items():
        architectures = report.get("supported_architectures")
        if not isinstance(architectures, list) or not all(
                isinstance(architecture, str) for architecture in architectures):
            raise RepairError(
                "unsupported_architecture",
                f"Runtime {runtime!r} has malformed supported_architectures")
        missing = tuple(architecture for architecture in architectures
                        if architecture not in registered)
        if missing:
            raise RepairError(
                "unsupported_architecture",
                f"Runtime {runtime!r} declares unregistered architectures: "
                f"{list(missing)}; registered architectures: {list(registered)}")
        bindings[runtime] = tuple(architectures)
    return bindings


RUNTIME_ARCHITECTURE_BINDINGS: MappingProxyType[str, tuple[str, ...]] = MappingProxyType(
    _architecture_bindings()
)


RUNTIME_PROTOCOL_BINDINGS: MappingProxyType[str, tuple[str, ...]] = MappingProxyType(
    _protocol_bindings()
)


RUNTIME_CAPABILITIES: MappingProxyType[str, dict] = MappingProxyType({
    runtime: deepcopy(report)
    for runtime, report in _RUNTIME_DEFINITIONS.items()
})


def runtime_names() -> tuple[str, ...]:
    return tuple(RUNTIME_CAPABILITIES)


def capability_report(runtime: str) -> dict:
    try:
        return deepcopy(RUNTIME_CAPABILITIES[runtime])
    except (KeyError, TypeError) as exc:
        raise RepairError("unsupported_runtime",
                          f"Unsupported firmware runtime: {runtime}") from exc


def is_authoritative(runtime: str) -> bool:
    return bool(capability_report(runtime)["capabilities"]["authoritative_verification"])


def supports(runtime: str, capability: str) -> bool:
    report = capability_report(runtime)
    capabilities = report["capabilities"]
    if not isinstance(capabilities, dict):
        raise RepairError("unsupported_runtime", "Malformed runtime capabilities")
    try:
        known = capability in capabilities
    except TypeError as exc:
        raise RepairError("unsupported_runtime",
                          f"Unknown runtime capability: {capability}") from exc
    if not known:
        raise RepairError("unsupported_runtime",
                          f"Unknown runtime capability: {capability}")
    return bool(capabilities[capability])


def supports_architecture(runtime: str, architecture: str) -> bool:
    return architecture in capability_report(runtime)["supported_architectures"]


def supports_protocol(runtime: str, protocol: str) -> bool:
    return protocol in capability_report(runtime)["supported_protocols"]


def validate_capability_report(report: dict) -> dict:
    if not isinstance(report, dict) or report.get("schema") != RUNTIME_CAPABILITY_SCHEMA:
        raise RepairError("preparation_failed",
                          f"Expected {RUNTIME_CAPABILITY_SCHEMA}")
    runtime = report.get("runtime")
    try:
        known_runtime = runtime in RUNTIME_CAPABILITIES
    except TypeError as exc:
        raise RepairError("unsupported_runtime",
                          f"Unsupported firmware runtime: {runtime}") from exc
    if not known_runtime:
        raise RepairError("unsupported_runtime",
                          f"Unsupported firmware runtime: {runtime}")
    expected = RUNTIME_CAPABILITIES[runtime]
    if report != expected:
        raise RepairError("preparation_failed",
                          f"Runtime capability mismatch: {runtime}")
    return report
