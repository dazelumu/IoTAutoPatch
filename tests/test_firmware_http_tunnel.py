from __future__ import annotations

import json
import socket

from repair_tool.firmware.session.http_tunnel import framed_delivery


class Peer:
    def __init__(self, incoming: list[bytes]):
        self.incoming = list(incoming)
        self.sent = bytearray()
        self.events: list[tuple[str, object]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, value):
        self.events.append(("timeout", value))

    def sendall(self, data):
        self.sent.extend(data)

    def shutdown(self, how):
        self.events.append(("shutdown", how))

    def recv(self, size):
        self.events.append(("recv", size))
        return self.incoming.pop(0) if self.incoming else b""


def test_framed_delivery_half_closes_request_before_reading_response():
    request = b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
    response = b"HTTP/1.0 200 OK\r\n\r\nok"
    client = Peer([json.dumps({"request_hex": request.hex(),
                               "deadline": 1e99}).encode() + b"\n"])
    upstream = Peer([response, b""])

    framed_delivery(client, lambda: upstream, b"")

    envelope = json.loads(client.sent.decode())
    assert envelope["receive"] == "eof"
    assert bytes.fromhex(envelope["response_hex"]) == response
    assert upstream.sent == request
    shutdown_index = upstream.events.index(("shutdown", socket.SHUT_WR))
    first_read_index = next(index for index, event in enumerate(upstream.events)
                            if event[0] == "recv")
    assert shutdown_index < first_read_index
