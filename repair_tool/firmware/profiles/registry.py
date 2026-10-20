"""Closed device-profile registry.

A profile is the device-specific bring-up contract. Core session/runtime code
must not import a profile directly; it resolves one through this registry.
The legacy ``firmware.adapter`` value remains a compatibility alias while
generated cases migrate to explicit profile identities.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceProfile:
    name: str
    aliases: tuple[str, ...]
    runtime: str
    architecture: str
    protocol: str
    target: str
    supervisor_module: str
    brand: str
    model: str
    firmware_version: str
    protocols: tuple[str, ...] = ()

    def supported_protocols(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.protocol, *self.protocols)))


DIR825_B_2_03 = DeviceProfile(
    name="dlink/dir825b-2.03",
    aliases=("dir825",),
    runtime="native-proot-mips32be",
    architecture="mips32be",
    protocol="http-ascii-get-head-port80",
    protocols=("http-ascii-auth-form-multi-step-port80",),
    target="sbin/httpd",
    supervisor_module="repair_tool.firmware.profiles.dlink.dir825b_2_03.device_supervisor",
    brand="dlink",
    model="dir825b",
    firmware_version="2.03",
)

_PROFILES = (DIR825_B_2_03,)
_BY_NAME = {profile.name: profile for profile in _PROFILES}
_BY_ALIAS = {
    alias: profile
    for profile in _PROFILES
    for alias in (*profile.aliases, profile.name)
}


def profile_names() -> tuple[str, ...]:
    return tuple(profile.name for profile in _PROFILES)


def resolve_profile(value: str) -> DeviceProfile:
    try:
        return _BY_ALIAS[value]
    except KeyError as exc:
        raise ValueError(
            f"unsupported firmware profile {value!r}; registered profiles: "
            f"{list(profile_names())}"
        ) from exc
