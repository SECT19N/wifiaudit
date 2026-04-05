"""
core/scanner.py — Passive network scanner using airodump-ng
Detects visible and hidden (SSID-less) networks.
"""

import csv
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class AccessPoint:
    bssid: str
    ssid: str  # Empty string = hidden SSID
    channel: int
    frequency: str
    encryption: str  # WPA2, WPA, WEP, OPN
    cipher: str
    auth: str
    power: int  # Signal in dBm (negative)
    beacons: int
    data_packets: int
    hidden: bool = False
    clients: list[str] = field(default_factory=list)

    @property
    def display_ssid(self) -> str:
        if self.hidden:
            return f"<hidden> [{self.bssid}]"
        return self.ssid or f"<empty> [{self.bssid}]"

    @property
    def signal_bar(self) -> str:
        """ASCII signal strength."""
        pwr = abs(self.power)
        if pwr < 50:
            return "████ Excellent"
        if pwr < 60:
            return "███░ Good"
        if pwr < 70:
            return "██░░ Fair"
        if pwr < 80:
            return "█░░░ Weak"
        return "░░░░ Poor"


class Scanner:
    """
    Runs airodump-ng in background, parses CSV output,
    calls on_update(list[AccessPoint]) periodically.
    """

    def __init__(self, iface: str, on_update: Callable, channel: int = 0):
        self.iface = iface
        self.on_update = on_update
        self.channel = channel
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._tmpdir = tempfile.mkdtemp(prefix="wifiaudit_")
        self._prefix = os.path.join(self._tmpdir, "scan")
        self.access_points: dict[str, AccessPoint] = {}

    def start(self):
        self._stop_event.clear()
        cmd = [
            "airodump-ng",
            "--write",
            self._prefix,
            "--output-format",
            "csv",
            "--write-interval",
            "1",
        ]
        if self.channel:
            cmd += ["--channel", str(self.channel)]
        cmd.append(self.iface)

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._thread = threading.Thread(target=self._poll_csv, daemon=True)
        self._thread.start()

    def _poll_csv(self):
        csv_path = self._prefix + "-01.csv"
        while not self._stop_event.is_set():
            time.sleep(1.5)
            if os.path.exists(csv_path):
                aps = self._parse_csv(csv_path)
                self.access_points = {ap.bssid: ap for ap in aps}
                self.on_update(list(self.access_points.values()))

    def _parse_csv(self, path: str) -> list[AccessPoint]:
        aps = []
        clients_section = False
        client_rows = []

        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            return aps

        sections = content.split("\r\n\r\n")
        if not sections:
            return aps

        # ── AP Section ──
        ap_lines = sections[0].strip().splitlines()
        if len(ap_lines) < 2:
            return aps

        reader = csv.DictReader(ap_lines)
        for row in reader:
            try:
                bssid = row.get(" BSSID", row.get("BSSID", "")).strip()
                if not bssid or bssid == "BSSID":
                    continue
                ssid = row.get(" ESSID", "").strip()
                hidden = ssid == "" or ssid == "\\x00" * len(ssid)
                try:
                    pwr = int(row.get(" Power", "-100").strip())
                except ValueError:
                    pwr = -100
                try:
                    ch = int(row.get(" channel", "0").strip())
                except ValueError:
                    ch = 0
                try:
                    beacons = int(row.get(" # beacons", "0").strip())
                except ValueError:
                    beacons = 0
                try:
                    data = int(row.get(" # IV", "0").strip())
                except ValueError:
                    data = 0

                enc = row.get(" Privacy", "").strip()
                cipher = row.get(" Cipher", "").strip()
                auth = row.get(" Authentication", "").strip()

                ap = AccessPoint(
                    bssid=bssid,
                    ssid=ssid,
                    channel=ch,
                    frequency="",
                    encryption=enc,
                    cipher=cipher,
                    auth=auth,
                    power=pwr,
                    beacons=beacons,
                    data_packets=data,
                    hidden=hidden,
                )
                aps.append(ap)
            except Exception:
                continue

        # ── Client Section ──
        if len(sections) > 1:
            client_lines = sections[1].strip().splitlines()
            client_reader = csv.DictReader(client_lines)
            for row in client_reader:
                try:
                    mac = row.get(" Station MAC", "").strip()
                    assoc = row.get(" BSSID", "").strip()
                    if mac and assoc and assoc != "(not associated)":
                        for ap in aps:
                            if ap.bssid == assoc:
                                ap.clients.append(mac)
                except Exception:
                    continue

        return aps

    def stop(self):
        self._stop_event.set()
        if self._proc:
            self._proc.terminate()
            self._proc.wait()
        if self._thread:
            self._thread.join(timeout=3)
        # Cleanup temp files
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)
