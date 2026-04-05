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


def enable_monitor_mode(iface: str) -> tuple[bool, str]:
    """
    Enable monitor mode on given interface.
    Returns (success, monitor_interface_name).
    Uses airmon-ng check kill first, then airmon-ng start.
    """
    # Kill conflicting processes
    _run(["airmon-ng", "check", "kill"])

    stdout, stderr, rc = _run(["airmon-ng", "start", iface])
    if rc != 0:
        return False, stderr

    # Parse new interface name (usually wlan0mon or wlan0)
    mon_iface = iface + "mon"
    for line in stdout.splitlines():
        m = re.search(r"monitor mode vif enabled.*?on\s+\[(\w+)\]", line)
        if m:
            mon_iface = m.group(1)
            break
        m = re.search(r"monitor mode enabled on\s+(\w+)", line)
        if m:
            mon_iface = m.group(1)
            break

    return True, mon_iface


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
