"""Session HTTP transport: pathname Unix socket relay.

Client bytes (tool side) are relayed verbatim to 127.0.0.1:80 inside the
adapter's private network namespace. Every pipeline request is thereby
bound to exactly one session; no host TCP ports are opened.
"""
from __future__ import annotations

import selectors
import json
import socket
import threading
import time

TUNNEL_MAGIC = b"REPAIR-TUNNEL/1\n"
MAX_RESPONSE = 65536


def framed_delivery(client, connect_upstream, prefix):
    """Keep transport metadata off the firmware's unmodified HTTP wire."""
    request = bytearray(prefix)
    deadline = time.monotonic() + 30
    while b"\n" not in request:
        client.settimeout(max(0.001, deadline - time.monotonic()))
        block = client.recv(4096)
        if not block or len(request) + len(block) > 512 * 1024:
            raise ValueError("Invalid framed request")
        request.extend(block)
    envelope = json.loads(request.split(b"\n", 1)[0])
    raw = bytes.fromhex(envelope["request_hex"])
    deadline = min(deadline, float(envelope["deadline"]))
    response = bytearray()
    receive = "upstream_error"
    try:
        upstream = connect_upstream()
        with upstream:
            upstream.settimeout(max(0.001, deadline - time.monotonic()))
            upstream.sendall(raw)
            # A complete request has been sent and every supported request
            # carries Connection: close. Half-closing our write side lets a
            # close-delimited HTTP/1.0 response prove EOF instead of being
            # reported as an ambiguous socket timeout after its final byte.
            try:
                upstream.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                upstream.settimeout(remaining)
                block = upstream.recv(min(4096, MAX_RESPONSE + 1 - len(response)))
                if not block:
                    receive = "eof"
                    break
                response.extend(block)
                if len(response) > MAX_RESPONSE:
                    receive = "size_limit"
                    break
    except OSError as exc:
        receive = "timeout" if isinstance(exc, TimeoutError) else "upstream_error"
    client.settimeout(1)
    client.sendall(json.dumps({"receive": receive,
                               "response_hex": bytes(response[:MAX_RESPONSE]).hex()}).encode() + b"\n")


def relay(left, right, stopped):
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)
    try:
        while not stopped.is_set():
            for key, _ in selector.select(timeout=0.5):
                block = key.fileobj.recv(65536)
                if not block:
                    selector.unregister(key.fileobj)
                    try:
                        key.data.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    if not selector.get_map():
                        return
                    continue
                key.data.sendall(block)
    finally:
        selector.close()


class RelayServer:
    def __init__(self, listener, connect_upstream):
        self.listener = listener
        self.connect_upstream = connect_upstream
        self.stopped = threading.Event()
        self.connections = set()
        self.lock = threading.Lock()

    def start(self):
        self.listener.listen(32)
        self.listener.settimeout(0.5)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()

    def handle(self, client):
        upstream = None
        try:
            client.settimeout(30)
            prefix = bytearray()
            while len(prefix) < len(TUNNEL_MAGIC):
                block = client.recv(len(TUNNEL_MAGIC) - len(prefix))
                if not block:
                    return
                prefix.extend(block)
                if not TUNNEL_MAGIC.startswith(prefix):
                    break
            if bytes(prefix) == TUNNEL_MAGIC:
                framed_delivery(client, self.connect_upstream, b"")
                return
            upstream = self.connect_upstream()
            upstream.settimeout(30)
            upstream.sendall(prefix)
            with self.lock:
                self.connections.update((client, upstream))
            relay(client, upstream, self.stopped)
        except (OSError, ValueError, KeyError, TypeError):
            pass
        finally:
            with self.lock:
                self.connections.discard(client)
                if upstream:
                    self.connections.discard(upstream)
            client.close()
            if upstream:
                upstream.close()

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=2)
        with self.lock:
            for connection in tuple(self.connections):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


def isolated_http_tunnel(path):
    """HTTP-over-Unix-socket server for this session."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    server = RelayServer(listener, lambda: socket.create_connection(("127.0.0.1", 80), timeout=3))
    server.start()
    return server
