"""DIR-825 wireless control backend simulation (lab protocol implementation).

The original httpd/wpatalk stay unmodified. This is NOT hostapd or real WPS:
it answers the control-protocol subset httpd's CGI path depends on
(ATTACH/DETACH/PING/CONFIGME + completion notification), so the vendor Web
stack runs unmodified under emulation. Protocol evidence: libwpa_ctrl
ATTACH/DETACH check exact b'OK\\n'; hostapd PING/FAIL replies; wpatalk event
prefix parser.
"""
from __future__ import annotations

import json
import os
import re
import selectors
import socket
import threading
import time
from pathlib import Path

SUCCESS_EVENT = b'<2>CTRL-REQ-EAP-WPS-SUCCESS]-Complete EAP-WPS protocol '


def valid_pin(pin: str) -> bool:
    """Eight decimal digits with WPS alternating 3/1 checksum (firmware rule)."""
    return bool(re.fullmatch(r"[0-9]{8}", pin)) and sum(
        int(value) * (3 if index % 2 == 0 else 1)
        for index, value in enumerate(pin)) % 10 == 0


class WirelessControlBackend:
    def __init__(self, socket_path, evidence_dir, completion_delay=0.25):
        self.socket_path = Path(socket_path)
        self.evidence_dir = Path(evidence_dir)
        self.completion_delay = completion_delay
        self.emit_completion_events = True
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.attached = set()
        self.pending = []
        self.sequence = 0
        self.sock = None
        self.thread = None
        self.state = {"backend": "lab wireless control protocol implementation",
                      "real_wireless_pairing": False, "accepted_jobs": [],
                      "rejected_requests": [], "last_completed_job": None}

    def record(self, kind, **values):
        self.sequence += 1
        item = {"sequence": self.sequence, "kind": kind, "time": time.time(), **values}
        with (self.evidence_dir / "protocol.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(item) + "\n")
        return item

    def save_state(self):
        temporary = self.evidence_dir / "state.json.new"
        temporary.write_text(json.dumps(self.state, indent=2))
        os.replace(temporary, self.evidence_dir / "state.json")

    def start(self):
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if len(os.fsencode(self.socket_path)) >= 108:
            raise ValueError("Unix socket path is too long")
        # Never remove an existing socket; it may belong to a running session.
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(str(self.socket_path))
        self.sock.setblocking(False)
        with self.lock:
            self.record("start", socket_path=str(self.socket_path),
                        guest_socket="/var/run/hostapd/ath0")
            self.save_state()
        self.thread = threading.Thread(target=self.serve, name="dir825-wireless-control", daemon=True)
        self.thread.start()

    def reply(self, peer, data):
        self.sock.sendto(data, peer)
        self.record("response", peer=peer, payload=data.decode("ascii"))

    def reject(self, peer, command, reason, unknown=False):
        self.state["rejected_requests"].append({"command": command, "reason": reason})
        self.record("rejected", peer=peer, command=command, reason=reason)
        self.reply(peer, b"UNKNOWN COMMAND\n" if unknown else b"FAIL\n")
        self.save_state()

    def handle(self, data, peer):
        try:
            command = data.decode("ascii")
        except UnicodeDecodeError:
            self.reject(peer, data.hex(), "non-ASCII command")
            return
        self.record("request", peer=peer, payload=command)
        if len(data) > 256 or not peer:
            self.reject(peer, command, "invalid size or unnamed client")
        elif command == "ATTACH":
            self.attached.add(peer)
            self.reply(peer, b"OK\n")
        elif command == "DETACH":
            if peer not in self.attached:
                self.reject(peer, command, "not attached")
            else:
                self.attached.remove(peer)
                self.reply(peer, b"OK\n")
        elif command == "PING":
            self.reply(peer, b"PONG\n")
        elif command.startswith("CONFIGME"):
            match = re.fullmatch(r"CONFIGME pin=([0-9]{8}) clean", command)
            if peer not in self.attached:
                self.reject(peer, command, "not attached")
            elif not match:
                self.reject(peer, command, "unsupported or malformed CONFIGME parameters")
            elif not valid_pin(match.group(1)):
                self.reject(peer, command, "invalid WPS PIN checksum")
            else:
                job = {"job_id": len(self.state["accepted_jobs"]) + 1,
                       "pin": match.group(1), "clean": True, "peer": peer,
                       "status": "accepted", "real_wireless_pairing": False}
                self.state["accepted_jobs"].append(job)
                self.record("accepted", **job)
                self.reply(peer, b"OK\n")
                self.pending.append((time.monotonic() + self.completion_delay, peer, job))
                self.save_state()
        else:
            self.reject(peer, command, "command outside implemented observed subset", unknown=True)

    def complete_due(self):
        now = time.monotonic()
        remaining = []
        for deadline, peer, job in self.pending:
            if now < deadline:
                remaining.append((deadline, peer, job))
                continue
            if not self.emit_completion_events:
                job["status"] = "accepted_no_notification_test"
                self.record("notification_suppressed", job_id=job["job_id"])
            elif peer not in self.attached:
                job["status"] = "client_detached_before_completion"
                self.record("completion_failed", job_id=job["job_id"], reason=job["status"])
            else:
                try:
                    self.sock.sendto(SUCCESS_EVENT, peer)
                    job["status"] = "completed_simulated"
                    self.state["last_completed_job"] = dict(job)
                    self.record("notification", peer=peer, job_id=job["job_id"],
                                payload=SUCCESS_EVENT.decode("ascii"), real_wireless_pairing=False)
                except OSError as exc:
                    job["status"] = "notification_delivery_failed"
                    self.record("completion_failed", job_id=job["job_id"], error=str(exc))
            self.save_state()
        self.pending = remaining

    def serve(self):
        selector = selectors.DefaultSelector()
        selector.register(self.sock, selectors.EVENT_READ)
        try:
            while not self.stop_event.is_set():
                for _ in selector.select(timeout=0.05):
                    data, peer = self.sock.recvfrom(4096)
                    with self.lock:
                        try:
                            self.handle(data, peer)
                        except OSError as exc:
                            self.record("communication_error", peer=peer, error=str(exc))
                with self.lock:
                    self.complete_due()
        except Exception as exc:            # noqa: BLE001 - evidence, then stop
            with self.lock:
                self.record("backend_error", error=str(exc))
            self.stop_event.set()
        finally:
            selector.close()

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.state))

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=2)
        if self.sock is not None:
            self.sock.close()
        self.socket_path.unlink(missing_ok=True)
        with self.lock:
            self.record("stop")
            self.save_state()
