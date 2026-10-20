"""Protocol drivers for request validation and wire encoding.

The registry is intentionally closed.  The original DIR-825 driver accepts
ASCII GET/HEAD requests without a body; the management-plane driver adds a
bounded form POST and cookie replay contract for authenticated multi-step
scenarios.  It still does not expose arbitrary headers or raw TCP.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Protocol
from urllib.parse import quote

from ..config import RepairError


PROTOCOL_CAPABILITY_SCHEMA = "protocol-capability-v1"
HTTP_ASCII_GET_HEAD_PORT80 = "http-ascii-get-head-port80"
HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80 = "http-ascii-auth-form-multi-step-port80"
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
MAX_FORM_FIELDS = 32
MAX_FORM_BODY_BYTES = 16384
MAX_FORM_VALUE_BYTES = 4096
MAX_COOKIE_PAIRS = 16


class ProtocolDriver(Protocol):
    """Request contract for a protocol supported by a runtime."""

    name: str

    def capability_report(self) -> dict: ...

    def validate_request(self, request: dict) -> None: ...

    def encode_request(self, request: dict) -> bytes: ...

    def parse_response(self, raw: bytes, method: str = "GET") -> object: ...


class HttpAsciiGetHeadPort80Driver:
    """The existing DIR-825 HTTP/1.1 request encoder, unchanged."""

    name = HTTP_ASCII_GET_HEAD_PORT80

    def capability_report(self) -> dict:
        return {
            "schema": PROTOCOL_CAPABILITY_SCHEMA,
            "protocol": "http",
            "methods": ["GET", "HEAD"],
            "ascii_path_only": True,
            "body": False,
            "ports": [80],
            "multi_step": False,
        }

    def validate_request(self, request: dict) -> None:
        if not isinstance(request, dict) or set(request) - {"method", "path", "host", "port"}:
            raise RepairError("preparation_failed", "Invalid request fields")
        method, path = request.get("method", "GET"), request.get("path", "/")
        host = request.get("host", "router")
        if method not in {"GET", "HEAD"} or not isinstance(path, str) or not path.startswith("/"):
            raise RepairError("preparation_failed", "Requests require GET/HEAD and an absolute path")
        if not isinstance(host, str) or not host or any(
                ord(char) <= 32 or ord(char) >= 127 for char in host):
            raise RepairError("preparation_failed",
                              "Host must be ASCII without whitespace/control bytes")
        if isinstance(request.get("port"), bool) or not isinstance(request.get("port", 80), int):
            raise RepairError("preparation_failed", "port must be an integer")
        port = request.get("port", 80)
        if not 1 <= port <= 65535:
            raise RepairError("preparation_failed", "port must be in 1..65535")
        if port != 80:
            raise RepairError(
                "preparation_failed",
                "The current firmware HTTP transport supports port 80 only")
        if any(ord(char) <= 32 or ord(char) >= 127 for char in path):
            raise RepairError("preparation_failed", "Path must be ASCII without whitespace/control bytes")

    def encode_request(self, request: dict) -> bytes:
        self.validate_request(request)
        method = request.get("method", "GET")
        path = request.get("path", "/")
        host = request.get("host", "router")
        return (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

    def parse_response(self, raw: bytes, method: str = "GET"):
        # Reuse the acceptance parser; this driver adds no response semantics.
        from .http import parse_response
        return parse_response(raw, method)


HTTP_ASCII_GET_HEAD_PORT80_DRIVER = HttpAsciiGetHeadPort80Driver()


class HttpAsciiAuthFormMultiStepPort80Driver:
    """Bounded HTTP management-plane request encoder.

    A request may carry a form mapping and previously captured cookies, but
    all potentially dangerous bytes are urlencoded by this driver.  The model
    and operator plans never provide a raw body or arbitrary header value.
    """

    name = HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80

    def capability_report(self) -> dict:
        return {
            "schema": PROTOCOL_CAPABILITY_SCHEMA,
            "protocol": "http",
            "methods": ["GET", "HEAD", "POST"],
            "ascii_path_only": True,
            "body": "form-urlencoded",
            "content_types": [FORM_CONTENT_TYPE],
            "ports": [80],
            "multi_step": True,
            "cookie_capture_replay": True,
            "max_form_fields": MAX_FORM_FIELDS,
            "max_form_value_bytes": MAX_FORM_VALUE_BYTES,
            "max_body_bytes": MAX_FORM_BODY_BYTES,
            "marker_kinds": ["empty_file"],
            "raw_tcp": False,
        }

    @staticmethod
    def _ascii_token(value: str, label: str, *, header: bool = False) -> None:
        if not isinstance(value, str) or not value or len(value) > 256:
            raise RepairError("preparation_failed", f"{label} is invalid")
        forbidden = set(";=,") if header else set("\r\n\t")
        if any(ord(char) <= 32 or ord(char) >= 127 or char in forbidden
               for char in value):
            raise RepairError(
                "preparation_failed",
                f"{label} must be ASCII without whitespace/control bytes")

    def _validate_common(self, request: dict) -> tuple[str, str, str, int]:
        allowed = {"method", "path", "host", "port", "cookies", "referer"}
        if "form" in request or "content_type" in request:
            allowed |= {"form", "content_type"}
        if not isinstance(request, dict) or set(request) - allowed:
            raise RepairError("preparation_failed", "Invalid request fields")
        method = request.get("method", "GET")
        path = request.get("path", "/")
        host = request.get("host", "router")
        if method not in {"GET", "HEAD", "POST"} or not isinstance(path, str) \
                or not path.startswith("/"):
            raise RepairError(
                "preparation_failed",
                "Requests require GET/HEAD/POST and an absolute path")
        self._ascii_token(host, "Host", header=False)
        if any(ord(char) <= 32 or ord(char) >= 127 for char in path):
            raise RepairError(
                "preparation_failed",
                "Path must be ASCII without whitespace/control bytes")
        if isinstance(request.get("port"), bool) or \
                not isinstance(request.get("port", 80), int):
            raise RepairError("preparation_failed", "port must be an integer")
        port = request.get("port", 80)
        if not 1 <= port <= 65535:
            raise RepairError("preparation_failed", "port must be in 1..65535")
        if port != 80:
            raise RepairError(
                "preparation_failed",
                "The current firmware HTTP transport supports port 80 only")
        referer = request.get("referer")
        if referer is not None:
            if (not isinstance(referer, str) or not referer or len(referer) > 2048
                    or any(ord(char) <= 32 or ord(char) >= 127
                           for char in referer)):
                raise RepairError(
                    "preparation_failed",
                    "Referer must be bounded ASCII without control bytes")
        return method, path, host, port

    def validate_request(self, request: dict) -> None:
        method, _, _, _ = self._validate_common(request)
        if request.get("content_type", FORM_CONTENT_TYPE) != FORM_CONTENT_TYPE:
            raise RepairError(
                "preparation_failed",
                f"POST content type must be {FORM_CONTENT_TYPE}")
        form = request.get("form", {})
        if not isinstance(form, dict) or len(form) > MAX_FORM_FIELDS:
            raise RepairError(
                "preparation_failed",
                f"form must be an object with at most {MAX_FORM_FIELDS} fields")
        for name, value in form.items():
            self._ascii_token(name, "Form field name", header=False)
            if not isinstance(value, str):
                raise RepairError("preparation_failed",
                                  "Form values must be strings")
            if len(value.encode("utf-8", "strict")) > MAX_FORM_VALUE_BYTES:
                raise RepairError(
                    "preparation_failed",
                    f"Form value {name!r} exceeds {MAX_FORM_VALUE_BYTES} bytes")
        cookies = request.get("cookies", {})
        if not isinstance(cookies, dict) or len(cookies) > MAX_COOKIE_PAIRS:
            raise RepairError(
                "preparation_failed",
                f"cookies must be an object with at most {MAX_COOKIE_PAIRS} pairs")
        for name, value in cookies.items():
            self._ascii_token(name, "Cookie name", header=True)
            self._ascii_token(value, "Cookie value", header=True)
        if form and method != "POST":
            raise RepairError("preparation_failed",
                              "Only POST requests may carry a form body")
        if method == "POST" and not form:
            raise RepairError("preparation_failed", "POST requires a form object")
        if len(self._encode_form(form)) > MAX_FORM_BODY_BYTES:
            raise RepairError("preparation_failed",
                              f"Encoded form body exceeds {MAX_FORM_BODY_BYTES} bytes")

    @staticmethod
    def _encode_form(form: dict[str, str]) -> bytes:
        pairs = [
            (quote(name, safe="-_.~", encoding="ascii", errors="strict"),
             quote(value, safe="-_.~", encoding="utf-8", errors="strict"))
            for name, value in form.items()
        ]
        return "&".join(f"{name}={value}" for name, value in pairs).encode("ascii")

    def encode_request(self, request: dict) -> bytes:
        self.validate_request(request)
        method = request.get("method", "GET")
        path = request.get("path", "/")
        host = request.get("host", "router")
        lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        if request.get("referer") is not None:
            lines.append(f"Referer: {request['referer']}")
        cookies = request.get("cookies", {})
        if cookies:
            lines.append("Cookie: " + "; ".join(
                f"{name}={value}" for name, value in cookies.items()))
        if method == "POST":
            body = self._encode_form(request["form"])
            lines.extend([
                "Content-Type: " + FORM_CONTENT_TYPE,
                f"Content-Length: {len(body)}",
            ])
        else:
            body = b""
        lines.extend(["Connection: close", ""])
        return ("\r\n".join(lines) + "\r\n").encode("ascii") + body

    def parse_response(self, raw: bytes, method: str = "GET"):
        from .http import parse_response
        return parse_response(raw, method)


HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80_DRIVER = (
    HttpAsciiAuthFormMultiStepPort80Driver())


PROTOCOL_DRIVERS: MappingProxyType[str, ProtocolDriver] = MappingProxyType({
    HTTP_ASCII_GET_HEAD_PORT80_DRIVER.name: HTTP_ASCII_GET_HEAD_PORT80_DRIVER,
    HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80_DRIVER.name:
        HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80_DRIVER,
})


def protocol_names() -> tuple[str, ...]:
    return tuple(PROTOCOL_DRIVERS)


def protocol_driver(protocol: str) -> ProtocolDriver:
    try:
        return PROTOCOL_DRIVERS[protocol]
    except (KeyError, TypeError) as exc:
        raise RepairError(
            "protocol_unsupported",
            f"Unsupported firmware protocol: {protocol!r}; "
            f"registered protocols: {list(PROTOCOL_DRIVERS)}",
        ) from exc


def capability_report(protocol: str) -> dict:
    return protocol_driver(protocol).capability_report()


def supports_protocol(protocol: str) -> bool:
    try:
        return protocol in PROTOCOL_DRIVERS
    except TypeError:
        return False


def validate_capability_report(report: dict) -> dict:
    if not isinstance(report, dict):
        raise RepairError("preparation_failed",
                          f"Expected {PROTOCOL_CAPABILITY_SCHEMA}")
    if report.get("schema") != PROTOCOL_CAPABILITY_SCHEMA:
        raise RepairError("preparation_failed",
                          f"Expected {PROTOCOL_CAPABILITY_SCHEMA}")
    for driver in PROTOCOL_DRIVERS.values():
        if report == driver.capability_report():
            return report
    raise RepairError(
        "preparation_failed",
        f"Protocol capability mismatch: {report.get('protocol')!r}")
