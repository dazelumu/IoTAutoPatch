"""Firmware-mode configuration schema, validation and doctor checks.

Config parsing owns types, paths and mode constraints only. Environment
checks (tools, rehost support) belong to firmware_doctor, never here.
"""
from __future__ import annotations

from pathlib import Path

from ..arch.names import (MIPS32BE, MIPS32BE_E_FLAGS_ABI_MASK,
                          MIPS32BE_E_FLAGS_ABI_O32,
                          MIPS32BE_E_FLAGS_MICROMIPS)
from ..config import RepairError
from .protocol import (HTTP_ASCII_GET_HEAD_PORT80,
                       HTTP_ASCII_AUTH_FORM_MULTI_STEP_PORT80, protocol_names)
from .profiles.registry import resolve_profile

CHECK_LIMIT = 100
CURRENT_PROTOCOL = HTTP_ASCII_GET_HEAD_PORT80


def validate_firmware_config(cfg: dict, config_path: Path) -> None:
    """Validate the firmware section after generic defaults are merged."""
    fw = cfg["firmware"]
    if not fw["mode"]:
        return
    for key in ("rootfs", "adapter", "target"):
        value = fw[key]
        if not isinstance(value, str) or not value.strip():
            raise RepairError("preparation_failed", f"firmware.{key} is required in firmware mode")
    try:
        profile = resolve_profile(fw["adapter"])
    except ValueError as exc:
        raise RepairError("preparation_failed", str(exc)) from exc
    rootfs = Path(fw["rootfs"])
    if not rootfs.is_dir():
        raise RepairError("preparation_failed", f"firmware.rootfs is not a directory: {rootfs}")
    output = Path(cfg["output"]["directory"])
    if output == rootfs or output in rootfs.parents or rootfs in output.parents:
        raise RepairError("preparation_failed",
                          "firmware.rootfs and output.directory must not contain "
                          "each other; run results must not mutate the source rootfs")
    target = fw["target"]
    if target.startswith("/") or ".." in Path(target).parts or not (rootfs / target).is_file():
        raise RepairError("preparation_failed",
                          f"firmware.target must be a rootfs-relative path to an existing file")
    if target != profile.target:
        raise RepairError("preparation_failed",
                          f"The {profile.name} profile requires "
                          f"firmware.target={profile.target}")
    target_path = rootfs / target
    components = [target_path, *target_path.parents]
    if any(path.is_symlink() for path in components if path != rootfs
           and rootfs in path.parents) or not target_path.resolve().is_relative_to(rootfs.resolve()):
        raise RepairError("preparation_failed",
                          "firmware.target must be a regular file inside the rootfs, "
                          "not a symbolic link")
    configured_protocol = fw.get("protocol", CURRENT_PROTOCOL)
    if configured_protocol not in protocol_names():
        raise RepairError("protocol_unsupported",
                          f"Unsupported firmware.protocol: {configured_protocol}")
    if configured_protocol not in profile.supported_protocols():
        raise RepairError(
            "protocol_unsupported",
            f"The {profile.name} profile does not support protocol "
            f"{configured_protocol}")
    _validate_checks(fw.get("checks"), configured_protocol)
    if cfg["project"]["path"] is not None:
        raise RepairError("preparation_failed",
                          "firmware.mode excludes project.path; the rehosted firmware is the target")
    poc = Path(cfg["poc"]["path"]) if cfg["poc"]["path"] is not None else None
    if poc is None:
        raise RepairError("preparation_failed",
                          "firmware.mode requires poc.path (the original PoC script, analyzed read-only)")
    if not poc.is_file():
        raise RepairError("preparation_failed",
                          f"firmware.mode poc.path must be an existing file: {poc}")


def _validate_checks(checks, protocol: str = CURRENT_PROTOCOL) -> None:
    """Fixed functional acceptance checks; authored by the operator, never by the model."""
    from .protocol import protocol_driver

    if not isinstance(checks, list) or not 1 <= len(checks) <= CHECK_LIMIT:
        raise RepairError("preparation_failed",
                          "firmware.checks must contain 1..100 fixed checks")
    for check in checks:
        if not isinstance(check, dict) or set(check) - {
                "protocol", "request", "steps", "statuses", "contains"}:
            raise RepairError("preparation_failed", "Invalid fixed check fields")
        check_protocol = check.get("protocol", protocol)
        if check_protocol not in protocol_names():
            raise RepairError("protocol_unsupported",
                              f"Unsupported fixed-check protocol: {check_protocol}")
        if ("request" in check) == ("steps" in check):
            raise RepairError("preparation_failed",
                              "Fixed check requires exactly one of request or steps")
        if check_protocol != protocol:
            raise RepairError("preparation_failed",
                              "Fixed checks must use firmware.protocol")
        request = check.get("request")
        driver = protocol_driver(check_protocol)
        if request is not None:
            if not isinstance(request, dict):
                raise RepairError("preparation_failed",
                                  "Fixed check requires a request object")
            driver.validate_request(request)
        else:
            from .http_multi_step import validate_steps
            validate_steps(check.get("steps"), protocol=check_protocol)
        statuses = check.get("statuses")
        if not isinstance(statuses, list) or not statuses or \
                not all(type(code) is int and 100 <= code <= 599 for code in statuses):
            raise RepairError("preparation_failed", "Fixed check requires expected HTTP statuses")
        if not isinstance(check.get("contains", ""), str):
            raise RepairError("preparation_failed", "Fixed check contains must be text")


def _architecture_facts(target: Path) -> dict:
    """Read only the neutral ELF identity needed by the capability gate."""
    try:
        with target.open("rb") as stream:
            data = stream.read(64)
    except OSError as exc:
        return {"candidate": None, "elf": {},
                "reason": f"cannot read target: {exc}"}
    if len(data) < 40 or data[:4] != b"\x7fELF":
        return {"candidate": None, "elf": {},
                "reason": "target is not a readable ELF image"}
    elf_class = {1: "ELF32", 2: "ELF64"}.get(data[4])
    endianness = {1: "little", 2: "big"}.get(data[5])
    if elf_class is None or endianness is None:
        return {"candidate": None,
                "elf": {"class_code": data[4], "data_code": data[5]},
                "reason": "target has an unsupported ELF identity encoding"}
    machine_code = int.from_bytes(data[18:20], "big" if endianness == "big"
                                  else "little")
    machine = {8: "MIPS", 40: "ARM", 183: "AArch64"}.get(
        machine_code, str(machine_code))
    flags_offset = 36 if elf_class == "ELF32" else 48
    if len(data) < flags_offset + 4:
        return {"candidate": None,
                "elf": {"class": elf_class, "endianness": endianness,
                        "machine": machine},
                "reason": "target has a truncated ELF header"}
    e_flags = int.from_bytes(data[flags_offset:flags_offset + 4],
                             "big" if endianness == "big" else "little")
    micromips = bool(e_flags & MIPS32BE_E_FLAGS_MICROMIPS)
    o32 = e_flags & MIPS32BE_E_FLAGS_ABI_MASK == MIPS32BE_E_FLAGS_ABI_O32
    candidate = MIPS32BE if (
            elf_class == "ELF32" and endianness == "big"
            and machine_code == 8 and o32 and not micromips) else None
    abi = "o32" if machine_code == 8 and elf_class == "ELF32" and o32 else None
    reason = None
    if candidate is None and (elf_class, endianness, machine_code) == (
            "ELF32", "big", 8):
        reason = ("unsupported MIPS ABI or instruction encoding; "
                  f"e_flags={e_flags:#x}; only MIPS32BE o32 is registered")
    return {"candidate": candidate,
            "elf": {"class": elf_class, "endianness": endianness,
                    "machine": machine, "machine_code": machine_code,
                    "abi": abi, "e_flags": e_flags, "micromips": micromips},
            "reason": None if candidate is not None else (
                reason if reason is not None else
                f"unregistered ELF identity {elf_class}/{endianness}/{machine}")}


def _protocol_support(fw: dict) -> dict:
    from .protocol import protocol_driver
    from .http_multi_step import validate_steps

    selected = fw.get("protocol", CURRENT_PROTOCOL)
    driver = protocol_driver(selected)
    configured_checks = fw.get("checks")
    if not isinstance(configured_checks, list) or not configured_checks:
        return {"supported": False,
                "reason": "no fixed checks are available for protocol validation"}
    invalid = []
    try:
        for index, check in enumerate(configured_checks):
            request = check.get("request") if isinstance(check, dict) else None
            try:
                if request is not None:
                    driver.validate_request(request)
                else:
                    validate_steps(check.get("steps"), protocol=selected)
            except RepairError as exc:
                invalid.append({"check": index, "error": str(exc)[:300]})
    except (TypeError, ValueError) as exc:
        return {"supported": False, "reason": f"invalid checks: {exc}"}
    if invalid:
        return {"supported": False, "invalid_checks": invalid,
                "reason": "one or more requests exceed the registered protocol capability"}
    return {"supported": True, "validated_checks": len(configured_checks)}


def _capability_diagnosis(fw: dict, target: Path, *,
                          target_elf_valid: bool) -> dict:
    """Compose registry facts without changing the DIR-825 execution path."""
    from ..arch.registry import architecture_names
    from .protocol import protocol_names
    from .runtime import (capability_report, is_authoritative,
                          runtime_names, supports_architecture,
                          supports_protocol)

    runtimes = []
    for name in runtime_names():
        report = capability_report(name)
        runtimes.append({
            "runtime": name,
            "authoritative_verification": is_authoritative(name),
            "supported_architectures": report["supported_architectures"],
            "supported_protocols": report["supported_protocols"],
        })

    profile = resolve_profile(fw["adapter"])
    selected_runtime = profile.runtime
    architecture = _architecture_facts(target)
    selected_architecture = (architecture["candidate"]
                             if target_elf_valid
                             and architecture["candidate"] is not None else None)
    protocol = _protocol_support(fw)
    registered_architectures = tuple(architecture_names())
    registered_protocols = tuple(protocol_names())

    runtime_registered = selected_runtime in runtime_names()
    runtime_architecture = bool(
        runtime_registered and supports_architecture(selected_runtime,
                                                     selected_architecture))
    runtime_protocol = bool(
        runtime_registered and supports_protocol(
            selected_runtime, fw.get("protocol", CURRENT_PROTOCOL)))
    architecture_registered = selected_architecture in registered_architectures
    protocol_registered = fw.get("protocol", CURRENT_PROTOCOL) in registered_protocols
    profile_protocol_supported = fw.get("protocol", CURRENT_PROTOCOL) in profile.supported_protocols()
    selected_protocol_supported = bool(
        protocol_registered
        and protocol.get("supported", False)
        and runtime_protocol)

    unsupported = []
    if not runtime_registered:
        unsupported.append("runtime")
    if not (architecture_registered and runtime_architecture):
        unsupported.append("architecture")
    if not (selected_protocol_supported and profile_protocol_supported):
        unsupported.append("protocol")

    runtime_view = {
        "selected": selected_runtime,
        "registered": runtime_registered,
        "supports_architecture": runtime_architecture,
        "supports_protocol": runtime_protocol,
        "authoritative_verification": (
            is_authoritative(selected_runtime) if runtime_registered else False),
    }
    if not runtime_registered:
        runtime_view["reason"] = (
            f"adapter {fw['adapter']!r} is not bound to a registered runtime")
    architecture_view = {
        "selected": selected_architecture,
        "detected": architecture["elf"],
        "registered": architecture_registered,
        "runtime_supported": runtime_architecture,
        "supported": architecture_registered and runtime_architecture,
    }
    if not target_elf_valid:
        reasons = ["target ELF validation failed"]
        if architecture["reason"]:
            reasons.append(architecture["reason"])
        architecture_view["reason"] = "; ".join(reasons)
    elif architecture["reason"]:
        architecture_view["reason"] = architecture["reason"]
    protocol_view = {
        "selected": fw.get("protocol", CURRENT_PROTOCOL),
        "profile_supported": fw.get("protocol", CURRENT_PROTOCOL)
        in profile.supported_protocols(),
        "registered": protocol_registered,
        "runtime_supported": runtime_protocol,
        **protocol,
    }
    supported = not unsupported
    return {
        "registered_runtimes": runtimes,
        "registered_architectures": list(registered_architectures),
        "registered_protocols": list(registered_protocols),
        "case": {
            "runtime": runtime_view,
            "architecture": architecture_view,
            "protocol": protocol_view,
            "status": "supported" if supported else "unsupported",
            "unsupported": unsupported,
        },
        "note": ("Capability support is a repair prerequisite, not a repair "
                 "or verification result."),
    }


def firmware_doctor(cfg: dict) -> dict:
    """Firmware-mode readiness: WSL tools, materials and adapter support.

    Reports facts; never mutates state. A not_ready result must stop run.
    """
    import platform
    import shutil
    import subprocess
    import sys

    from ..execution import child_env

    checks: dict = {"platform": platform.platform(),
                    "linux": sys.platform.startswith("linux"),
                    "model": cfg["model"]["name"],
                    "firmware": {}}
    status = "ready"
    if not checks["linux"]:
        checks["firmware"]["linux"] = False
        status = "not_ready"
    fw = cfg["firmware"]
    rootfs = Path(fw["rootfs"])
    try:
        profile = resolve_profile(fw["adapter"])
    except ValueError as exc:
        raise RepairError("preparation_failed", str(exc)) from exc
    checks["firmware"].update({
        "adapter": fw["adapter"],
        "profile": profile.name,
        "rootfs": str(rootfs),
        "rootfs_present": rootfs.is_dir(),
        "target": fw["target"],
        "target_present": (rootfs / fw["target"]).is_file(),
        "target_elf_valid": False,
    })
    if not checks["firmware"]["rootfs_present"] or not checks["firmware"]["target_present"]:
        status = "not_ready"
    else:
        try:
            from .runtimes.native_proot_mips32be.loader import executable_mappings
            executable_mappings(rootfs / fw["target"])
            checks["firmware"]["target_elf_valid"] = True
        except (OSError, RuntimeError, ValueError) as exc:
            checks["firmware"]["target_elf_valid"] = False
            checks["firmware"]["target_elf_error"] = str(exc)[:500]
            status = "not_ready"
    checks["capabilities"] = _capability_diagnosis(
        fw, rootfs / fw["target"],
        target_elf_valid=checks["firmware"]["target_elf_valid"])
    if checks["capabilities"]["case"]["status"] != "supported":
        status = "not_ready"
    tools = {name: shutil.which(name) for name in (
        "qemu-mips", "proot", "unshare", "ip", "clang", "llvm-objdump")}
    checks["tools"] = tools
    if not all(tools.values()):
        checks["missing_tools"] = [name for name, path in tools.items() if not path]
        status = "not_ready"
    # The MIPS cross target is required for candidate generation.
    if tools["clang"]:
        try:
            probe = subprocess.run([tools["clang"], "--print-targets"], capture_output=True,
                                   text=True, timeout=10, env=child_env(""))
            checks["mips_backend"] = probe.returncode == 0 and "mips" in probe.stdout.lower()
        except (OSError, subprocess.TimeoutExpired):
            checks["mips_backend"] = False
        if not checks.get("mips_backend"):
            status = "not_ready"
    if checks["linux"] and tools["unshare"]:
        try:
            probe = subprocess.run([
                tools["unshare"], "--user", "--map-root-user", "--net",
                "--pid", "--fork", "--mount-proc", "true"],
                capture_output=True, text=True, timeout=10,
                env=child_env(""))
            checks["unshare_namespaces"] = probe.returncode == 0
            if probe.returncode != 0:
                checks["unshare_error"] = (probe.stderr or probe.stdout)[-500:]
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks["unshare_namespaces"] = False
            checks["unshare_error"] = str(exc)[:500]
        if not checks["unshare_namespaces"]:
            status = "not_ready"
    from ..config import model_secret
    key_present = bool(model_secret(cfg))
    checks["api_key_present"] = key_present
    if not key_present:
        checks["missing"] = checks.get("missing", []) + ["model credential (api_key or api_key_env)"]
        status = "not_ready"
    checks["status"] = status
    return checks
