"""Small HTTP/1.x response parser used by firmware acceptance checks."""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class ParsedResponse:
    """The final (non-1xx) response with transfer framing removed."""

    status: int
    headers: dict[bytes, tuple[bytes, ...]]
    body: bytes


def _headers(lines: list[bytes]) -> dict[bytes, tuple[bytes, ...]] | None:
    collected: dict[bytes, list[bytes]] = {}
    for line in lines:
        name, colon, value = line.partition(b":")
        if not colon or not re.fullmatch(
                rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            return None
        collected.setdefault(name.lower(), []).append(value.strip())
    return {name: tuple(values) for name, values in collected.items()}


def _chunked_body(body: bytes) -> bytes | None:
    decoded = bytearray()
    cursor = 0
    while True:
        end = body.find(b"\r\n", cursor)
        if end < 0:
            return None
        size_text = body[cursor:end].split(b";", 1)[0]
        if not re.fullmatch(rb"[0-9a-fA-F]+", size_text):
            return None
        size = int(size_text, 16)
        cursor = end + 2
        if size == 0:
            remainder = body[cursor:]
            if remainder == b"\r\n":
                return bytes(decoded)
            if not remainder.endswith(b"\r\n\r\n"):
                return None
            trailer_lines = remainder[:-4].split(b"\r\n")
            if _headers(trailer_lines) is None:
                return None
            return bytes(decoded)
        if cursor + size + 2 > len(body) or \
                body[cursor + size:cursor + size + 2] != b"\r\n":
            return None
        decoded.extend(body[cursor:cursor + size])
        cursor += size + 2


def parse_response(data: bytes, method: str = "GET") -> ParsedResponse | None:
    """Parse one complete HTTP/1.x response from already-received bytes.

    Informational responses are skipped. Chunked transfer framing is decoded
    so content assertions operate on the entity body, never response headers.
    ``None`` means the bytes are malformed, ambiguous or incomplete.
    """
    while True:
        head, separator, body = data.partition(b"\r\n\r\n")
        if not separator:
            return None
        lines = head.split(b"\r\n")
        match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: .*)?", lines[0])
        if not match:
            return None
        status = int(match[1])
        headers = _headers(lines[1:])
        if headers is None:
            return None
        if 100 <= status < 200:
            if status == 101:
                return None
            data = body
            continue
        if method == "HEAD" or status in {204, 304}:
            return (ParsedResponse(status, headers, b"")
                    if not body else None)
        lengths = headers.get(b"content-length", ())
        encodings = headers.get(b"transfer-encoding", ())
        if encodings:
            if lengths or b",".join(encodings).lower() != b"chunked":
                return None
            decoded = _chunked_body(body)
            return (ParsedResponse(status, headers, decoded)
                    if decoded is not None else None)
        if lengths:
            values = [part.strip() for value in lengths
                      for part in value.split(b",")]
            if not all(re.fullmatch(rb"[0-9]+", value) for value in values):
                return None
            sizes = set(map(int, values))
            if len(sizes) != 1 or len(body) != next(iter(sizes)):
                return None
        # With no framing headers the body is close-delimited. The caller's
        # receive state decides whether the close was actually observed.
        return ParsedResponse(status, headers, body)


def response_complete(data: bytes, method: str, receive: str) -> bool:
    """Whether the receive state confirms the HTTP framing of this response.

    A socket timeout is not transport completion, but the framed firmware
    tunnel can have already captured a complete self-delimiting HTTP response.
    Accept ``timeout`` only when the parser confirms that the response has
    complete Content-Length, chunked, HEAD, 204, or 304 framing. Responses
    whose body is close-delimited still require an explicit completion state.
    """
    if receive not in {"eof", "response", "complete", "timeout"}:
        return False
    parsed = parse_response(data, method)
    if parsed is None:
        return False
    if receive != "timeout":
        return True
    return bool(
        parsed.headers.get(b"content-length")
        or parsed.headers.get(b"transfer-encoding")
        or method == "HEAD"
        or parsed.status in {204, 304}
    )
