"""M6 real-session acceptance: verify.py against the real DIR-825 session.

Fixed checks + plan replay on the original firmware, then a same-session
rollback roundtrip (replace with the same baseline bytes must keep identity).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repair_tool.firmware.plan import validate_plan
from repair_tool.firmware.rehost import SessionControl, SessionSupervisor
from repair_tool.firmware.verify import replay_plan, run_fixed_checks

ROOTFS = Path("/home/lumu/firmware-lab/dir825-b-2.03/work/rootfs-full")
CHECKS = [{"request": {"path": "/"}, "statuses": [200],
           "contains": "WIRELESS ROUTER | LOGIN"}]
PLAN = validate_plan({
    "analysis": "long static .gif path overflows a fixed buffer",
    "requests": [
        {"id": "control_home", "method": "GET", "path": "/", "expect": "response"},
        {"id": "control_short", "method": "GET", "path": "/AAAA(30).gif",
         "expect": "response"},
        {"id": "trigger", "method": "GET", "path": "/" + "A" * 205 + ".gif",
         "expect": "fatal_exit"},
    ],
    "confirmations": ["trigger"]})


@pytest.mark.slow
@pytest.mark.skipif(not ROOTFS.is_dir(), reason="DIR-825 lab rootfs not present")
def test_real_fixed_checks_and_rollback_replay(tmp_path):
    session = tmp_path / "session"
    with SessionSupervisor(ROOTFS, session):
        control = SessionControl(session)
        baseline_sha = control.target_sha()
        # 1. Operator fixed checks pass on the original firmware.
        fixed = run_fixed_checks(control, CHECKS, tmp_path / "fixed")
        assert fixed["passed"]
        # 2. Same-bytes replace keeps identity (rollback path is sound).
        baseline_copy = tmp_path / "baseline-httpd"
        baseline_copy.write_bytes((session / "rootfs" / "sbin" / "httpd").read_bytes())
        control.replace_target(baseline_copy)
        assert control.target_sha() == baseline_sha
        # 3. Plan replay on the ORIGINAL firmware must FAIL (trigger still
        #    kills it) -- the verifier rejects an unrepaired target.
        with pytest.raises(Exception) as excinfo:
            replay_plan(control, PLAN, tmp_path / "replay", exit_timeout=15.0)
        assert "new_fatal_exit" in str(excinfo.value) or "replay" in str(excinfo.value)
        # 4. After the fault, a restart restores service; fixed checks pass.
        control.restart()
        assert control.target_sha() == baseline_sha
        fixed2 = run_fixed_checks(control, CHECKS, tmp_path / "fixed2")
        assert fixed2["passed"]
