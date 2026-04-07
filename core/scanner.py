"""
core/scanner.py — Passive network scanner using airodump-ng
Detects visible and hidden (SSID-less) networks.
"""

import csv
import os
import re
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

    def __init__(
        self,
        iface: str,
        on_update: Callable,
        on_error: Optional[Callable[[str], None]] = None,
        channel: int = 0,
        band: str = "abg",  # a=5GHz, b/g=2.4GHz — abg covers both
    ):
        self.iface = iface
        self.on_update = on_update
        self.on_error = on_error
        self.channel = channel
        self.band = band
        self._proc: Optional[subprocess.Popen] = None
        self._poll_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._tmpdir = tempfile.mkdtemp(prefix="wifiaudit_scan_")
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
            "3",  # 3s — stable, no file contention
        ]
        if self.channel:
            # Locked channel: fastest, no hopping at all
            cmd += ["--channel", str(self.channel)]
        else:
            # Band flag: abg = both 2.4GHz (b/g) and 5GHz (a)
            cmd += ["--band", self.band]

        cmd.append(self.iface)

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._poll_thread = threading.Thread(target=self._poll_csv, daemon=True)
        self._poll_thread.start()
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self):
        """Surface airodump-ng errors through the on_error callback."""
        if not self._proc or not self._proc.stderr:
            return
        for line in self._proc.stderr:
            if self._stop_event.is_set():
                break
            line = line.strip()
            if line and self.on_error:
                self.on_error(f"[airodump] {line}")

    def _poll_csv(self):
        csv_path = self._prefix + "-01.csv"
        while not self._stop_event.is_set():
            time.sleep(3)
            if os.path.exists(csv_path):
                try:
                    aps = self._parse_csv(csv_path)
                    if aps:
                        self.access_points = {ap.bssid: ap for ap in aps}
                        self.on_update(list(self.access_points.values()))
                except Exception as e:
                    if self.on_error:
                        self.on_error(f"[scanner] parse error: {e}")

    def _parse_csv(self, path: str) -> list[AccessPoint]:
        """
        Parse airodump-ng CSV output.

        The file has two sections separated by a blank line:
          1. Access points  — header starts with 'BSSID'
          2. Station/clients — header starts with 'Station MAC'

        All column names after the first have a leading space, e.g. ' ESSID'.
        We normalise by stripping every key before lookup.
        """
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                raw = f.read()
        except OSError:
            return []

        # Normalise line endings then split into sections on blank lines
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        sections = re.split(r"\n[ \t]*\n", raw.strip())

        aps: list[AccessPoint] = []

        if not sections:
            return aps

        # ── AP section ──
        ap_lines = [l for l in sections[0].splitlines() if l.strip()]
        if len(ap_lines) < 2:
            return aps

        try:
            reader = csv.DictReader(ap_lines)
            for row in reader:
                # Normalise keys: strip whitespace, lowercase
                r = {k.strip().lower(): v.strip() for k, v in row.items() if k}

                bssid = r.get("bssid", "")
                if not bssid or bssid.lower() == "bssid":
                    continue
                # Must look like a MAC address
                if not re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", bssid):
                    continue

                ssid = r.get("essid", "")
                # Hidden: empty, all-null-bytes, or whitespace only
                hidden = (
                    not ssid
                    or not ssid.strip()
                    or all(c == "\x00" for c in ssid)
                    or re.match(r"^[\x00\s]+$", ssid) is not None
                )

                def _int(key: str, fallback: int = 0) -> int:
                    try:
                        return int(r.get(key, str(fallback)))
                    except ValueError:
                        return fallback

                ap = AccessPoint(
                    bssid=bssid,
                    ssid=ssid if not hidden else "",
                    channel=_int("channel"),
                    frequency="",
                    encryption=r.get("privacy", ""),
                    cipher=r.get("cipher", ""),
                    auth=r.get("authentication", ""),
                    power=_int("power", -100),
                    beacons=_int("# beacons"),
                    data_packets=_int("# iv"),
                    hidden=hidden,
                )
                aps.append(ap)
        except Exception:
            pass

        # ── Station / client section ──
        if len(sections) > 1:
            sta_lines = [l for l in sections[1].splitlines() if l.strip()]
            if len(sta_lines) >= 2:
                try:
                    sta_reader = csv.DictReader(sta_lines)
                    ap_map = {ap.bssid: ap for ap in aps}
                    for row in sta_reader:
                        r = {k.strip().lower(): v.strip() for k, v in row.items() if k}
                        mac = r.get("station mac", "")
                        assoc_bssid = r.get("bssid", "")
                        if (
                            mac
                            and assoc_bssid
                            and assoc_bssid != "(not associated)"
                            and assoc_bssid in ap_map
                        ):
                            if mac not in ap_map[assoc_bssid].clients:
                                ap_map[assoc_bssid].clients.append(mac)
                except Exception:
                    pass

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
