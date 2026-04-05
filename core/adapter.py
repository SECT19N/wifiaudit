"""
core/adapter.py — Wireless adapter detection and monitor mode control
Uses: iw, ip, airmon-ng
"""

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class WirelessAdapter:
    name: str  # e.g. wlan0
    phy: str  # e.g. phy0
    driver: str
    chipset: str
    monitor_capable: bool
    in_monitor_mode: bool
    monitor_iface: Optional[str] = None  # e.g. wlan0mon


def _run(cmd: list[str]) -> tuple[str, str, int]:
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout, r.stderr, r.returncode


def list_interfaces() -> list[WirelessAdapter]:
    """Return all wireless interfaces using iw dev."""
    adapters = []
    stdout, _, rc = _run(["iw", "dev"])
    if rc != 0:
        return adapters

    current_iface = None
    current_phy = None

    for line in stdout.splitlines():
        phy_match = re.match(r"^phy#(\d+)", line)
        iface_match = re.match(r"\s+Interface\s+(\S+)", line)
        type_match = re.match(r"\s+type\s+(\S+)", line)

        if phy_match:
            current_phy = f"phy{phy_match.group(1)}"
        elif iface_match:
            current_iface = iface_match.group(1)
        elif type_match and current_iface and current_phy:
            mode = type_match.group(1)
            in_monitor = mode == "monitor"
            driver, chipset = _get_driver_chipset(current_phy)
            monitor_capable = _check_monitor_capable(current_phy)
            adapters.append(
                WirelessAdapter(
                    name=current_iface,
                    phy=current_phy,
                    driver=driver,
                    chipset=chipset,
                    monitor_capable=monitor_capable,
                    in_monitor_mode=in_monitor,
                    monitor_iface=current_iface if in_monitor else None,
                )
            )
            current_iface = None

    return adapters


def _get_driver_chipset(phy: str) -> tuple[str, str]:
    """Try to get driver/chipset info from iw phy."""
    stdout, _, _ = _run(["iw", "phy", phy, "info"])
    driver = "unknown"
    chipset = "unknown"
    for line in stdout.splitlines():
        if "driver" in line.lower():
            parts = line.strip().split()
            if len(parts) >= 2:
                driver = parts[-1]
    # Try ethtool as fallback
    return driver, chipset


def _check_monitor_capable(phy: str) -> bool:
    """Check if phy supports monitor mode."""
    stdout, _, _ = _run(["iw", "phy", phy, "info"])
    return "monitor" in stdout.lower()


def _get_all_ifaces() -> set[str]:
    """Return all current wireless interface names from iw dev."""
    stdout, _, _ = _run(["iw", "dev"])
    return set(re.findall(r"Interface\s+(\S+)", stdout))


def _find_monitor_ifaces() -> list[str]:
    """Return interfaces currently in monitor mode."""
    stdout, _, _ = _run(["iw", "dev"])
    result = []
    current_iface = None
    for line in stdout.splitlines():
        m = re.match(r"\s+Interface\s+(\S+)", line)
        if m:
            current_iface = m.group(1)
        t = re.match(r"\s+type\s+(\S+)", line)
        if t and current_iface:
            if t.group(1) == "monitor":
                result.append(current_iface)
            current_iface = None
    return result


def enable_monitor_mode(iface: str) -> tuple[bool, str]:
    """
    Enable monitor mode on given interface.
    Returns (success, monitor_interface_name).

    Strategy:
    1. Snapshot interfaces before
    2. airmon-ng check kill + airmon-ng start
    3. Snapshot after — the new or changed monitor iface is the answer
    4. Fall back to iw set monitor if airmon-ng didn't create a new iface
    """
    # Snapshot before
    ifaces_before = _get_all_ifaces()
    monitor_before = set(_find_monitor_ifaces())

    # Kill conflicting processes
    kill_out, _, _ = _run(["airmon-ng", "check", "kill"])

    # Start monitor mode
    stdout, stderr, rc = _run(["airmon-ng", "start", iface])

    # Give the kernel a moment to rename the interface
    import time

    time.sleep(1)

    # Snapshot after
    ifaces_after = _get_all_ifaces()
    monitor_after = set(_find_monitor_ifaces())

    # New interfaces that appeared = the monitor vif airmon-ng created
    new_ifaces = ifaces_after - ifaces_before
    new_monitor = monitor_after - monitor_before

    if new_monitor:
        mon_iface = sorted(new_monitor)[0]
        return True, mon_iface

    if new_ifaces:
        mon_iface = sorted(new_ifaces)[0]
        return True, mon_iface

    # airmon-ng may have converted the existing iface in-place (no rename)
    # Check if the original iface is now in monitor mode
    if iface in monitor_after:
        return True, iface

    # Last resort: try setting monitor mode directly with iw
    _run(["ip", "link", "set", iface, "down"])
    _, err, rc2 = _run(["iw", "dev", iface, "set", "type", "monitor"])
    _run(["ip", "link", "set", iface, "up"])
    if rc2 == 0:
        return True, iface

    # Give up — report what airmon-ng said
    return False, stderr or stdout or "Unknown error enabling monitor mode."


def disable_monitor_mode(mon_iface: str) -> tuple[bool, str]:
    """Restore managed mode."""
    stdout, stderr, rc = _run(["airmon-ng", "stop", mon_iface])
    if rc != 0:
        return False, stderr
    # Restart NetworkManager
    _run(["systemctl", "restart", "NetworkManager"])
    return True, "Managed mode restored."


def set_channel(iface: str, channel: int) -> bool:
    _, _, rc = _run(["iw", "dev", iface, "set", "channel", str(channel)])
    return rc == 0
