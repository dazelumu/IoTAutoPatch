from __future__ import annotations

import copy
import os
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

import yaml


class RepairError(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


DEFAULTS = {
    "project": {"path": None},
    "poc": {"path": None, "args": [], "command": None},
    "tests": {"external_path": None, "external_command": None, "project_command": None},
    "firmware": {"mode": False, "rootfs": None, "adapter": "dir825", "target": "sbin/httpd",
                 "protocol": "http-ascii-get-head-port80",
                 "poc_request_timeout": 10, "total_timeout_seconds": 1800,
                 "checks": [{"request": {"path": "/"}, "statuses": [200],
                             "contains": ""}],
                 "diagnostics": {"expose_to_model": False, "max_record_bytes": 32768,
                                 "max_page_size": 20, "imports": []}},
    "triage": {"output_root": None, "firmae": {"enabled": False, "executable": None,
                                                "work_root": None, "timeout_seconds": 3600,
                                                "required": False},
               "greenhouse": {"enabled": False, "executable": None,
                              "work_root": None, "timeout_seconds": 3600,
                              "required": False}},
    "build": {"mode": "auto", "command": None, "timeout_seconds": 180, "jobs": 2},
    "model": {"provider": "openai_compatible", "base_url": None, "name": None,
              "api_key": None, "api_key_env": "REPAIR_API_KEY", "request_timeout_seconds": 120,
              "max_output_tokens": 8192, "retries": 2, "stream": False,
              "total_timeout_seconds": 600, "reasoning_effort": None},
    "repair": {"max_rounds": 5, "max_changed_lines": 200, "context_max_bytes": 65536,
               # Firmware-only efficiency controls live in the software-level
               # repair section so one installation can tune them without
               # putting provider/runtime policy into every case file.  Source
               # mode deliberately ignores all firmware_* keys.
               "firmware_max_rounds": 3,
               "firmware_localize_queries": 16,
               "firmware_relocalize_queries": 8,
               "firmware_query_batch_size": 4,
               "firmware_no_progress_turns": 4,
               "firmware_decisive_site_inspections": 2,
               "firmware_decisive_site_discoveries": 2,
               "firmware_length_differential": False,
               "firmware_length_probe_limit": 8,
               "firmware_localize_timeout_seconds": 1800,
               "firmware_relocalize_timeout_seconds": 900,
               "firmware_repair_timeout_seconds": 600,
               "firmware_query_max_output_tokens": 32768,
               "firmware_query_reasoning_effort": "low",
               "firmware_length_recovery_reasoning_effort": "low",
               "firmware_registration_max_output_tokens": 8192,
               "firmware_registration_reasoning_effort": "low",
               "firmware_conclusion_max_output_tokens": 24576,
               "firmware_repair_max_output_tokens": 32768,
               "firmware_exploratory_observation_seconds": 5},
    "validation": {"baseline_runs": 3, "poc_runs": 3, "poc_timeout_seconds": 15,
                   "test_timeout_seconds": 120, "generate_tests": True,
                   "independent_evaluation": True},
    "execution": {"memory_limit_mb": 2048, "max_log_mb": 10},
    "output": {"directory": "./repair-results", "keep_round_projects": True},
}


def _software_config_path() -> Path | None:
    """Global software-level config: config.yaml next to the installed
    repair_tool package (the software root, e.g. ~/tools/project-vuln-repair).
    REPAIR_GLOBAL_CONFIG (path or empty string to disable) overrides the
    default location. Case YAMLs override its values; it never overrides
    anything itself."""
    override = os.environ.get("REPAIR_GLOBAL_CONFIG")
    if override is not None:
        if not override.strip():
            return None
        candidate = Path(override)
        if not candidate.is_file():
            raise RepairError("preparation_failed",
                              f"Software config must be an existing file: {candidate}")
        return candidate
    root = Path(__file__).resolve().parent.parent
    candidate = root / "config.yaml"
    return candidate if candidate.is_file() else None


def _merge_layer(cfg: dict, raw: dict, origin: str, *,
                 restrict_to: tuple[str, ...] | None = None) -> None:
    """Overlay one YAML layer (sections validated against DEFAULTS).

    restrict_to: for the software-level layer, limit which sections may be
    set there. Case-path-relative keys (project/poc/tests/output/firmware
    paths) belong to the case layer only."""
    for section, values in raw.items():
        if not isinstance(section, str) or section not in cfg:
            raise RepairError("preparation_failed",
                              f"Unknown or invalid section in {origin}: {section}")
        if not isinstance(values, dict):
            raise RepairError("preparation_failed",
                              f"Invalid section in {origin}: {section}")
        if restrict_to is not None and section not in restrict_to:
            raise RepairError("preparation_failed",
                              f"Section {section} is not allowed in {origin}; "
                              "the software-level config only accepts: "
                              f"{list(restrict_to)}")
        unknown = [key for key in values
                   if not isinstance(key, str) or key not in cfg[section]]
        if unknown:
            raise RepairError("preparation_failed",
                              f"Unknown keys in {origin} section {section}: "
                              f"{sorted(unknown, key=str)}")
        cfg[section].update(values)


def _validate_schema(value: Any, default: Any, label: str) -> None:
    """Validate merged values against the shape of DEFAULTS.

    List item semantics remain owned by the feature that consumes the list.
    This layer catches unknown nested keys and wrong scalar/container types
    before a late consumer such as diagnostics import sees them.
    """
    if isinstance(default, dict):
        if not isinstance(value, dict):
            raise RepairError("preparation_failed", f"{label} must be an object")
        unknown = [key for key in value
                   if not isinstance(key, str) or key not in default]
        if unknown:
            raise RepairError("preparation_failed",
                              f"Unknown keys in {label}: {sorted(unknown, key=str)}")
        for key, item in value.items():
            _validate_schema(item, default[key], f"{label}.{key}")
        return
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise RepairError("preparation_failed", f"{label} must be boolean")
        return
    if isinstance(default, int):
        minimum = 0 if label.endswith(".retries") else 1
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise RepairError("preparation_failed",
                              f"{label} must be an integer >= {minimum}")
        return
    if isinstance(default, str):
        if default is None:
            if value is not None and not isinstance(value, str):
                raise RepairError("preparation_failed", f"{label} must be text or null")
            return
        if not isinstance(value, str):
            raise RepairError("preparation_failed", f"{label} must be text")
        return
    if isinstance(default, list):
        if not isinstance(value, list):
            raise RepairError("preparation_failed", f"{label} must be an array")
        return
    if default is None:
        if label.endswith((".command", "_command")) and isinstance(value, list):
            if (not value or not all(isinstance(item, str) and item for item in value)):
                raise RepairError("preparation_failed",
                                  f"{label} must be a nonempty argv array")
            return
        if value is not None and not isinstance(value, str):
            raise RepairError("preparation_failed", f"{label} must be text or null")


def _contains_or_equals(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _resolve_triage_paths(cfg: dict, base: Path) -> None:
    triage = cfg.get("triage")
    if not isinstance(triage, dict):
        return
    for key in ("output_root",):
        value = triage.get(key)
        if isinstance(value, str) and value:
            path = Path(value)
            triage[key] = str((path if path.is_absolute() else base / path).resolve())
    for backend in ("firmae", "greenhouse"):
        values = triage.get(backend)
        if not isinstance(values, dict):
            continue
        for key in ("executable", "work_root"):
            value = values.get(key)
            if isinstance(value, str) and value:
                path = Path(value)
                values[key] = str((path if path.is_absolute() else base / path).resolve())


def _validate_writable_layout(cfg: dict, *, include_default_triage: bool,
                              base: Path) -> None:
    firmware = cfg.get("firmware", {})
    rootfs_value = firmware.get("rootfs") if isinstance(firmware, dict) else None
    if not isinstance(rootfs_value, str) or not rootfs_value:
        return
    rootfs = Path(rootfs_value).resolve()
    triage = cfg.get("triage", {})
    if not isinstance(triage, dict):
        triage = {}
    output_value = triage.get("output_root")
    if output_value is None and include_default_triage:
        output_value = "triage-results"
    writable = []
    if isinstance(output_value, str) and output_value:
        path = Path(output_value)
        writable.append((path if path.is_absolute() else base / path).resolve())
    for backend in ("firmae", "greenhouse"):
        values = triage.get(backend, {})
        if not isinstance(values, dict):
            continue
        work_value = values.get("work_root")
        if isinstance(work_value, str) and work_value:
            path = Path(work_value)
            writable.append((path if path.is_absolute() else base / path).resolve())
    repair_output = cfg.get("output", {}).get("directory")
    if isinstance(repair_output, str) and repair_output:
        writable.append(Path(repair_output).resolve())
    for index, left in enumerate(writable):
        for right in writable[index + 1:]:
            if _contains_or_equals(left, right):
                raise RepairError(
                    "preparation_failed",
                    "Triage/work/output directories must not contain each other")
        if _contains_or_equals(left, rootfs):
            raise RepairError(
                "preparation_failed",
                "Triage/work/output directories must not contain firmware.rootfs "
                "or be inside it")


def _load_yaml_mapping(path: Path, label: str) -> dict:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RepairError("preparation_failed",
                          f"Cannot read {label} {path}: {exc}") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RepairError("preparation_failed", f"{label} {path} root must be a mapping")
    return value


def load_config(path: str | Path) -> dict:
    path = Path(path).resolve()
    raw = _load_yaml_mapping(path, "configuration")
    cfg = copy.deepcopy(DEFAULTS)
    # Layer 1: software-level config.yaml (shared model credentials etc.).
    global_path = _software_config_path()
    if global_path is not None:
        layer = _load_yaml_mapping(global_path, "software config")
        _merge_layer(cfg, layer, str(global_path),
                     restrict_to=("model", "repair", "validation",
                                  "execution", "build"))
    # Layer 2: the case YAML always wins.
    _merge_layer(cfg, raw, str(path))
    for section, values in cfg.items():
        _validate_schema(values, DEFAULTS[section], section)
    if not isinstance(cfg["firmware"]["rootfs"], str) or not cfg["firmware"]["rootfs"]:
        if cfg["firmware"]["mode"]:
            raise RepairError("preparation_failed", "firmware.rootfs must be a path in firmware mode")
    else:
        cfg["firmware"]["rootfs"] = str((path.parent / cfg["firmware"]["rootfs"]).resolve())
    path_keys = [("poc", "path"), ("tests", "external_path"), ("output", "directory")]
    if not cfg["firmware"]["mode"]:
        path_keys.insert(0, ("project", "path"))
    for section, key in path_keys:
        value = cfg[section][key]
        if value is None and section == "tests":
            continue
        if not isinstance(value, str) or not value:
            raise RepairError("preparation_failed", f"{section}.{key} must be a path")
        cfg[section][key] = str((path.parent / value).resolve())
    _resolve_triage_paths(cfg, path.parent)
    _validate_writable_layout(cfg, include_default_triage=False, base=path.parent)
    from .firmware.case import validate_firmware_config
    validate_firmware_config(cfg, path)
    if cfg["firmware"]["mode"]:
        # Firmware mode: the rehosted image is the target; no source project.
        validate_model_config(cfg)
        cfg["config_path"] = str(path)
        return cfg
    project, output = Path(cfg["project"]["path"]), Path(cfg["output"]["directory"])
    if not project.is_dir() or not Path(cfg["poc"]["path"]).is_file():
        raise RepairError("preparation_failed", "Project must be a directory and PoC must be a file")
    if output == project or project in output.parents or output in project.parents:
        raise RepairError("preparation_failed", "Output and project paths must not contain each other")
    if cfg["tests"]["external_path"] and not Path(cfg["tests"]["external_path"]).exists():
        raise RepairError("preparation_failed", "External tests path does not exist")
    for section, key in (("build", "command"), ("poc", "command"),
                         ("tests", "external_command"), ("tests", "project_command")):
        value = cfg[section][key]
        if value is not None and (not isinstance(value, list) or not value or
                                  not all(isinstance(x, str) and x for x in value)):
            raise RepairError("preparation_failed", f"{section}.{key} must be a nonempty argv array")
    if not isinstance(cfg["poc"]["args"], list) or not all(isinstance(x, str) for x in cfg["poc"]["args"]):
        raise RepairError("preparation_failed", "poc.args must be an array of strings")
    if cfg["build"]["mode"] not in {"auto", "custom"}:
        raise RepairError("preparation_failed", "build.mode must be auto or custom")
    if cfg["build"]["mode"] == "custom" and not cfg["build"]["command"]:
        raise RepairError("preparation_failed", "custom build requires build.command")
    validate_model_config(cfg)
    cfg["config_path"] = str(path)
    return cfg


def load_triage_config(path: str | Path) -> dict:
    """Load only the case schema needed by import-only firmware triage.

    This path does not require model credentials, a PoC, fixed HTTP checks, or
    the Linux rehost toolchain.  It still validates the nested configuration
    schema and the rootfs/triage writable-layout boundary before triage can
    create an output directory.
    """
    path = Path(path).resolve()
    raw = _load_yaml_mapping(path, "configuration")
    cfg = copy.deepcopy(DEFAULTS)
    _merge_layer(cfg, raw, str(path))
    for section, values in cfg.items():
        _validate_schema(values, DEFAULTS[section], section)
    firmware = cfg["firmware"]
    if firmware["mode"] is not True:
        raise RepairError("preparation_failed",
                          "repair triage requires firmware.mode=true")
    rootfs_value = firmware.get("rootfs")
    if not isinstance(rootfs_value, str) or not rootfs_value:
        raise RepairError("preparation_failed",
                          "firmware.rootfs must be a path in firmware mode")
    firmware["rootfs"] = str((path.parent / rootfs_value).resolve())
    rootfs = Path(firmware["rootfs"])
    if not rootfs.is_dir():
        raise RepairError("preparation_failed",
                          f"firmware.rootfs is not a directory: {rootfs}")
    target = firmware.get("target")
    if not isinstance(target, str) or not target or target.startswith("/") \
            or ".." in Path(target).parts:
        raise RepairError("preparation_failed",
                          "firmware.target must be a rootfs-relative path")
    target_path = rootfs / target
    if (not target_path.is_file() or target_path.is_symlink()
            or not target_path.resolve().is_relative_to(rootfs.resolve())):
        raise RepairError("preparation_failed",
                          "firmware.target must be an existing regular file in rootfs")
    _resolve_triage_paths(cfg, path.parent)
    _validate_writable_layout(cfg, include_default_triage=True, base=path.parent)
    cfg["config_path"] = str(path)
    return cfg


def load_firmae_execute_config(path: str | Path) -> dict:
    """Load either a normal triage case or a Route-A intake template.

    A normal triage case already has a rootfs and uses ``load_triage_config``.
    A Route-A template intentionally leaves ``firmware.rootfs`` unset until
    ``repair intake`` materializes it; for FirmAE execute it is loaded with the
    stricter intake rules.  This keeps one template usable by both triage and
    intake without inventing a temporary rootfs.
    """
    path = Path(path).resolve()
    raw = _load_yaml_mapping(path, "FirmAE execute configuration")
    firmware = raw.get("firmware")
    rootfs_unset = (isinstance(firmware, dict)
                    and firmware.get("rootfs") is None)
    if rootfs_unset:
        return load_intake_config(path)
    return load_triage_config(path)


def load_intake_config(path: str | Path) -> dict:
    """Load a FirmAE intake template before a rootfs exists.

    Route A deliberately separates intake from triage.  The template describes
    the future firmware case (target, PoC, checks, model policy and triage
    locations), but ``firmware.rootfs`` must remain unset until ``repair
    intake`` materializes it.  Model credentials may be inherited from the
    software layer; this loader does not require the key to exist.
    """
    path = Path(path).resolve()
    raw = _load_yaml_mapping(path, "intake configuration")
    cfg = copy.deepcopy(DEFAULTS)
    global_path = _software_config_path()
    if global_path is not None:
        layer = _load_yaml_mapping(global_path, "software config")
        _merge_layer(cfg, layer, str(global_path),
                     restrict_to=("model", "repair", "validation",
                                  "execution", "build"))
    _merge_layer(cfg, raw, str(path))
    for section, values in cfg.items():
        _validate_schema(values, DEFAULTS[section], section)

    firmware = cfg["firmware"]
    if firmware["mode"] is not True:
        raise RepairError("preparation_failed", "repair intake requires firmware.mode=true")
    from .firmware.profiles.registry import resolve_profile
    try:
        profile = resolve_profile(firmware["adapter"])
    except ValueError as exc:
        raise RepairError("preparation_failed", str(exc)) from exc
    if profile.name != "dlink/dir825b-2.03":
        raise RepairError("preparation_failed",
                          "repair intake phase 1 requires profile "
                          "dlink/dir825b-2.03")
    if firmware["target"] != profile.target:
        raise RepairError("preparation_failed",
                          f"repair intake phase 1 requires firmware.target={profile.target}")
    if firmware.get("protocol") not in profile.supported_protocols():
        raise RepairError("protocol_unsupported",
                          f"repair intake profile {profile.name} does not support "
                          f"protocol {firmware.get('protocol')!r}")
    if firmware["rootfs"] is not None:
        raise RepairError("preparation_failed",
                          "intake template must leave firmware.rootfs unset; "
                          "repair intake will generate it")
    if cfg["project"]["path"] is not None:
        raise RepairError("preparation_failed", "firmware.mode excludes project.path")
    template_firmware = raw.get("firmware", {})
    if not isinstance(template_firmware, dict) or \
            "checks" not in template_firmware:
        raise RepairError("preparation_failed",
                          "intake template must explicitly author firmware.checks")

    poc = cfg["poc"]["path"]
    if not isinstance(poc, str) or not poc:
        raise RepairError("preparation_failed", "intake requires poc.path")
    cfg["poc"]["path"] = str((path.parent / poc).resolve())
    if not Path(cfg["poc"]["path"]).is_file():
        raise RepairError("preparation_failed",
                          f"intake poc.path is not an existing file: {cfg['poc']['path']}")
    if cfg["tests"]["external_path"] is not None:
        value = cfg["tests"]["external_path"]
        if not isinstance(value, str) or not value:
            raise RepairError("preparation_failed", "tests.external_path must be a path")
        cfg["tests"]["external_path"] = str((path.parent / value).resolve())
        if not Path(cfg["tests"]["external_path"]).exists():
            raise RepairError("preparation_failed", "External tests path does not exist")

    triage = cfg["triage"]["firmae"]
    if not triage["enabled"] or not triage["executable"] or not triage["work_root"]:
        raise RepairError("preparation_failed",
                          "intake requires triage.firmae enabled/executable/work_root")
    if not cfg["triage"]["output_root"]:
        cfg["triage"]["output_root"] = "triage-results"
    _resolve_triage_paths(cfg, path.parent)
    _validate_writable_layout(cfg, include_default_triage=False, base=path.parent)
    cfg["output"]["directory"] = str(
        (path.parent / cfg["output"]["directory"]).resolve())
    cfg["config_path"] = str(path)
    return cfg


def validate_model_config(cfg: dict) -> None:
    """Shared model validation; retain the source-mode configuration rules."""
    # Firmware localization calls target the configured GLM service and use
    # a project-specific effort policy. GLM supports low/high/max only.
    firmware_reasoning_efforts = (None, "low", "high", "max")
    if cfg["model"]["provider"] != "openai_compatible":
        raise RepairError("preparation_failed", "Only openai_compatible is implemented")
    if cfg["model"]["reasoning_effort"] not in (None, "low", "medium", "high", "xhigh", "max"):
        raise RepairError("preparation_failed", "Invalid model.reasoning_effort")
    recovery_effort = cfg["repair"]["firmware_length_recovery_reasoning_effort"]
    if recovery_effort not in firmware_reasoning_efforts:
        raise RepairError(
            "preparation_failed",
            "Invalid repair.firmware_length_recovery_reasoning_effort")
    query_effort = cfg["repair"]["firmware_query_reasoning_effort"]
    if query_effort not in firmware_reasoning_efforts:
        raise RepairError(
            "preparation_failed",
            "Invalid repair.firmware_query_reasoning_effort")
    registration_effort = cfg["repair"]["firmware_registration_reasoning_effort"]
    if registration_effort not in firmware_reasoning_efforts:
        raise RepairError(
            "preparation_failed",
            "Invalid repair.firmware_registration_reasoning_effort")
    for key in ("base_url", "name", "api_key_env"):
        if not isinstance(cfg["model"][key], str) or not cfg["model"][key]:
            raise RepairError("preparation_failed", f"model.{key} is required")
    inline = cfg["model"]["api_key"]
    if inline is not None and (not isinstance(inline, str) or not inline.strip()):
        raise RepairError("preparation_failed", "model.api_key must be a nonempty string or null")
    url = urlparse(cfg["model"]["base_url"])
    if url.scheme not in {"https", "http"} or not url.netloc or url.username or url.password or url.query:
        raise RepairError("preparation_failed", "model.base_url must be an HTTP(S) URL without credentials/query")
    if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise RepairError("preparation_failed", "Remote model endpoints require HTTPS")


def model_secret(cfg: dict) -> str:
    inline = cfg["model"].get("api_key")
    if isinstance(inline, str) and inline.strip():
        return inline
    return os.environ.get(cfg["model"]["api_key_env"], "")


def public_config(cfg: dict) -> dict:
    """Remove inline credentials from saved configuration."""
    result = copy.deepcopy(cfg)
    secret = model_secret(cfg)
    if secret:
        for section, values in result.items():
            if isinstance(values, dict):
                for key, value in values.items():
                    if isinstance(value, str):
                        values[key] = value.replace(secret, "<redacted>")
    result["model"]["api_key"] = None
    return result
