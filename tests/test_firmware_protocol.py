"""Protocol driver capability and DIR-825 HTTP compatibility tests (W7)."""
from __future__ import annotations

import pytest

from repair_tool.config import RepairError
from repair_tool.firmware.protocol import (HTTP_ASCII_GET_HEAD_PORT80,
                                           HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80,
                                           PROTOCOL_CAPABILITY_SCHEMA,
                                           capability_report,
                                           protocol_driver, protocol_names,
                                           supports_protocol,
                                           validate_capability_report)


DRIVER = protocol_driver(HTTP_ASCII_GET_HEAD_PORT80)
FORM_DRIVER = protocol_driver(HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80)


def test_registry_contains_exactly_the_two_http_drivers() -> None:
    assert protocol_names() == (
        HTTP_ASCII_GET_HEAD_PORT80, HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80)
    assert supports_protocol(HTTP_ASCII_GET_HEAD_PORT80)
    assert not supports_protocol(None)
    assert not supports_protocol("http-with-body")
    assert not supports_protocol("raw-tcp")
    assert not supports_protocol("udp")


def test_registry_is_closed_for_mutation() -> None:
    from repair_tool.firmware.protocol import PROTOCOL_DRIVERS

    with pytest.raises(TypeError):
        PROTOCOL_DRIVERS["udp"] = object()
    assert protocol_names() == (
        HTTP_ASCII_GET_HEAD_PORT80, HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80)


def test_capability_report_declares_exact_phase_one_boundaries() -> None:
    report = capability_report(HTTP_ASCII_GET_HEAD_PORT80)

    assert report == {
        "schema": PROTOCOL_CAPABILITY_SCHEMA,
        "protocol": "http",
        "methods": ["GET", "HEAD"],
        "ascii_path_only": True,
        "body": False,
        "ports": [80],
        "multi_step": False,
    }
    assert "multipart" not in report
    assert "raw_tcp" not in report
    assert "udp" not in report


def test_get_request_bytes_are_exact() -> None:
    assert DRIVER.encode_request({}) == (
        b"GET / HTTP/1.1\r\n"
        b"Host: router\r\n"
        b"Connection: close\r\n\r\n"
    )


def test_head_host_and_explicit_port_are_encoded_without_changes() -> None:
    request = {"method": "HEAD", "path": "/index.htm", "host": "router.local",
               "port": 80}
    assert DRIVER.encode_request(request) == (
        b"HEAD /index.htm HTTP/1.1\r\n"
        b"Host: router.local\r\n"
        b"Connection: close\r\n\r\n"
    )
    assert DRIVER.encode_request(request) == DRIVER.encode_request(
        {key: value for key, value in request.items() if key != "port"})


@pytest.mark.parametrize("invalid_request,message", [
    ({"method": "POST", "path": "/"}, "Requests require GET/HEAD"),
    ({"path": "no-slash"}, "Requests require GET/HEAD"),
    ({"path": "/", "port": 8080},
     "The current firmware HTTP transport supports port 80 only"),
    ({"path": "/x\r\nX: injected"}, "Path must be ASCII"),
    ({"path": "/", "host": "router\r\nX: injected"}, "Host must be ASCII"),
    ({"path": "/路由"}, "Path must be ASCII"),
    ({"path": "/", "extra": "forbidden"}, "Invalid request fields"),
])
def test_request_boundaries_reject_ambiguities(invalid_request: dict,
                                               message: str) -> None:
    with pytest.raises(RepairError) as caught:
        DRIVER.validate_request(invalid_request)

    assert caught.value.status == "preparation_failed"
    assert message in str(caught.value)


def test_port_errors_keep_their_existing_semantics() -> None:
    with pytest.raises(RepairError, match="port must be an integer"):
        DRIVER.validate_request({"path": "/", "port": True})
    with pytest.raises(RepairError, match="port must be in 1..65535"):
        DRIVER.validate_request({"path": "/", "port": 0})


def test_unknown_protocol_fails_explicitly() -> None:
    with pytest.raises(RepairError) as caught:
        protocol_driver("udp")

    assert caught.value.status == "protocol_unsupported"


def test_capability_report_is_detached_and_validated() -> None:
    report = capability_report(HTTP_ASCII_GET_HEAD_PORT80)
    report["body"] = True

    with pytest.raises(RepairError, match="Protocol capability mismatch"):
        validate_capability_report(report)
    assert capability_report(HTTP_ASCII_GET_HEAD_PORT80)["body"] is False


def test_non_object_capability_report_fails_cleanly() -> None:
    with pytest.raises(RepairError, match="protocol-capability-v1"):
        validate_capability_report(None)


def test_parse_response_reuses_existing_http_parser() -> None:
    parsed = DRIVER.parse_response(
        b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nhome")
    assert parsed is not None
    assert parsed.status == 200
    assert parsed.body == b"home"


def test_form_driver_capability_is_explicit_and_bounded() -> None:
    report = capability_report(HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80)

    assert report == {
        "schema": PROTOCOL_CAPABILITY_SCHEMA,
        "protocol": "http",
        "methods": ["GET", "HEAD", "POST"],
        "ascii_path_only": True,
        "body": "form-urlencoded",
        "content_types": ["application/x-www-form-urlencoded"],
        "ports": [80],
        "multi_step": True,
        "cookie_capture_replay": True,
        "max_form_fields": 32,
        "max_form_value_bytes": 4096,
        "max_body_bytes": 16384,
        "marker_kinds": ["empty_file"],
        "raw_tcp": False,
    }


def test_form_post_cookies_and_referer_are_deterministically_encoded() -> None:
    request = {
        "method": "POST",
        "path": "/apc_client_pin.cgi",
        "referer": "http://router/do_wps.asp",
        "cookies": {"uid": "0123"},
        "form": {"wps_pin": "';>/Q ;#", "empty": ""},
    }
    expected = (
        b"POST /apc_client_pin.cgi HTTP/1.1\r\n"
        b"Host: router\r\n"
        b"Referer: http://router/do_wps.asp\r\n"
        b"Cookie: uid=0123\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 37\r\n"
        b"Connection: close\r\n\r\n"
        b"wps_pin=%27%3B%3E%2FQ%20%3B%23&empty="
    )
    assert FORM_DRIVER.encode_request(request) == expected


@pytest.mark.parametrize("invalid_request,message", [
    ({"method": "POST", "path": "/", "form": {}, "content_type": "text/plain"},
     "POST content type must be application/x-www-form-urlencoded"),
    ({"method": "POST", "path": "/"}, "POST requires a form object"),
    ({"method": "GET", "path": "/", "form": {"x": "y"}},
     "Only POST requests may carry a form body"),
    ({"method": "POST", "path": "/", "form": {"x": "y"}, "extra": 1},
     "Invalid request fields"),
    ({"method": "POST", "path": "/", "form": {"x": "y"},
      "cookies": {"bad name": "v"}}, "Cookie name must be ASCII"),
    ({"method": "POST", "path": "/", "form": {"x": "y"},
      "referer": "http://router/\r\nX: y"}, "Referer must be bounded ASCII"),
])
def test_form_driver_rejects_unapproved_shapes(invalid_request: dict,
                                                message: str) -> None:
    with pytest.raises(RepairError) as caught:
        FORM_DRIVER.validate_request(invalid_request)

    assert caught.value.status == "preparation_failed"
    assert message in str(caught.value)
