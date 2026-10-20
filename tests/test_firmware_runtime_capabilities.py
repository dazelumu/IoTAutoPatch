"""Runtime capability registry contracts (W5)."""
from __future__ import annotations

import pytest

from repair_tool.config import RepairError
from repair_tool.arch.names import architecture_names
from repair_tool.arch.registry import MIPS32BE_BACKEND
from repair_tool.firmware.protocol import (HTTP_ASCII_GET_HEAD_PORT80,
                                           HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
                                           capability_report as protocol_capability,
                                           protocol_names)
from repair_tool.firmware.runtime import (RUNTIME_CAPABILITY_SCHEMA,
                                          RUNTIME_CAPABILITIES,
                                          RUNTIME_ARCHITECTURE_BINDINGS,
                                          RUNTIME_PROTOCOL_BINDINGS,
                                          NATIVE_PROOT_MIPS32BE as NATIVE_RUNTIME_DEFINITION,
                                          capability_report, is_authoritative,
                                          runtime_names, supports,
                                          supports_architecture,
                                          supports_protocol,
                                          validate_capability_report)


def test_registered_runtime_names() -> None:
    assert runtime_names() == ("native-proot-mips32be", "firmae", "greenhouse")
    assert architecture_names() == (MIPS32BE_BACKEND.name,)


def test_native_dir825_runtime_is_the_current_authority() -> None:
    report = capability_report("native-proot-mips32be")
    assert report["schema"] == RUNTIME_CAPABILITY_SCHEMA
    assert report["capabilities"]["authoritative_verification"] is True
    assert report["capabilities"]["transactional_mutation"] is True
    assert report["capabilities"]["rollback"] is True
    assert report["supported_architectures"] == ["mips32be"]
    assert report["supported_protocols"] == [
        "http-ascii-get-head-port80",
        "http-ascii-auth-form-multi-step-port80"]
    assert report["limits"] == {
        "http_port": 80, "request_ascii_only": True,
        "request_body": "form-urlencoded", "max_form_fields": 32,
        "max_form_body_bytes": 16384, "marker_kinds": ["empty_file"],
    }
    assert is_authoritative("native-proot-mips32be")


@pytest.mark.parametrize("runtime", ["firmae", "greenhouse"])
def test_external_runtimes_are_diagnostic_only(runtime: str) -> None:
    report = capability_report(runtime)
    assert report["capabilities"]["diagnostics"] is True
    assert report["capabilities"]["authoritative_verification"] is False
    assert report["limits"]["diagnostic_only"] is True
    assert not is_authoritative(runtime)
    assert not supports(runtime, "replace_target")


def test_native_runtime_supports_both_registered_http_protocols() -> None:
    runtime = "native-proot-mips32be"
    assert supports(runtime, "deliver_http_get_head")
    assert supports(runtime, "deliver_http_body")
    assert supports(runtime, "deliver_http_form_post")
    assert supports(runtime, "multi_step_http")
    assert supports(runtime, "cookie_session")
    assert supports(runtime, "side_effect_marker")
    assert not supports(runtime, "deliver_raw_tcp")
    assert supports_architecture(runtime, "mips32be")
    assert not supports_architecture(runtime, "arm32")
    assert supports_protocol(runtime, "http-ascii-get-head-port80")
    assert supports_protocol(
        runtime, HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80)
    assert not supports_protocol(runtime, "http-with-body")


def test_runtime_protocol_declarations_are_bound_to_registered_drivers() -> None:
    registered = protocol_names()
    for runtime in runtime_names():
        protocols = capability_report(runtime)["supported_protocols"]
        assert RUNTIME_PROTOCOL_BINDINGS[runtime] == tuple(protocols)
        assert all(protocol in registered for protocol in protocols)


def test_runtime_architecture_declarations_are_bound_to_registered_backends() -> None:
    registered = architecture_names()
    for runtime in runtime_names():
        architectures = capability_report(runtime)["supported_architectures"]
        assert RUNTIME_ARCHITECTURE_BINDINGS[runtime] == tuple(architectures)
        assert all(architecture in registered for architecture in architectures)


def test_native_runtime_limits_match_protocol_driver_capability() -> None:
    report = capability_report("native-proot-mips32be")

    assert report["supported_protocols"] == [
        HTTP_ASCII_GET_HEAD_PORT80, HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80]
    for protocol_name in report["supported_protocols"]:
        protocol = protocol_capability(protocol_name)
        assert report["limits"]["http_port"] == protocol["ports"][0]
        assert report["limits"]["request_ascii_only"] is protocol["ascii_path_only"]
    form = protocol_capability(HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80)
    assert report["limits"]["request_body"] == form["body"]
    assert report["limits"]["max_form_fields"] == form["max_form_fields"]
    assert report["limits"]["max_form_body_bytes"] == form["max_body_bytes"]


def test_runtime_registries_are_closed_and_reports_detached() -> None:
    with pytest.raises(TypeError):
        RUNTIME_CAPABILITIES["custom-runtime"] = {}
    with pytest.raises(TypeError):
        RUNTIME_PROTOCOL_BINDINGS["custom-runtime"] = ()
    with pytest.raises(TypeError):
        RUNTIME_ARCHITECTURE_BINDINGS["custom-runtime"] = ()

    NATIVE_RUNTIME_DEFINITION["supported_protocols"].append("udp")
    NATIVE_RUNTIME_DEFINITION["supported_architectures"].append("arm32")
    try:
        assert capability_report("native-proot-mips32be")["supported_protocols"] == [
            HTTP_ASCII_GET_HEAD_PORT80, HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80
        ]
        assert capability_report("native-proot-mips32be")["supported_architectures"] == [
            "mips32be"
        ]
    finally:
        NATIVE_RUNTIME_DEFINITION["supported_protocols"].pop()
        NATIVE_RUNTIME_DEFINITION["supported_architectures"].pop()

    report = capability_report("native-proot-mips32be")
    report["supported_protocols"].append("udp")
    report["limits"]["http_port"] = 8080
    assert capability_report("native-proot-mips32be")["supported_protocols"] == [
        HTTP_ASCII_GET_HEAD_PORT80, HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80
    ]
    assert capability_report("native-proot-mips32be")["limits"]["http_port"] == 80


def test_unknown_runtime_and_capability_are_rejected() -> None:
    with pytest.raises(RepairError, match="Unsupported firmware runtime"):
        capability_report("qemu-generic")
    with pytest.raises(RepairError, match="Unknown runtime capability"):
        supports("firmae", "authoritative_runtime")
    with pytest.raises(RepairError, match="Unsupported firmware runtime"):
        capability_report(["native-proot-mips32be"])
    with pytest.raises(RepairError, match="Unknown runtime capability"):
        supports("firmae", ["replace_target"])


def test_validate_rejects_changed_capability_report() -> None:
    report = capability_report("greenhouse")
    changed = {**report, "runtime": "greenhouse-copy"}
    with pytest.raises(RepairError, match="Unsupported firmware runtime"):
        validate_capability_report(changed)
