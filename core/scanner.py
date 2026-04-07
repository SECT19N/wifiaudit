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
    ssid: str
    channel: int
    frequency: str
    encryption: str
    cipher: str
    auth: str
    power: int
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
    def __init__(
        self,
        iface: str,
        on_update: Callable,
        on_error: Optional[Callable[[str], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        channel: int = 0,
    ):
        self.iface = iface
        self.on_update = on_update
        self.on_error = on_error
        self.on_status = on_status
        self.channel = int(channel) if channel else 0  # 🔥 force int
        self._proc: Optional[subprocess.Popen] = None
        self._poll_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._status_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._tmpdir = tempfile.mkdtemp(prefix="scan_")
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
            "1",  # 🔥 faster updates
            "--ignore-negative-one",  # 🔥 driver fix
        ]

        if self.channel:
            cmd += ["--channel", str(self.channel)]
        else:
            # 🔥 reliable hopping instead of --band
            cmd += ["--channel", "1,2,3,4,5,6,7,8,9,10,11,36,40,44,48"]

        cmd.append(self.iface)

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        import time

        time.sleep(1)
        print("PROCESS POLL:", self._proc.poll())

        self._poll_thread = threading.Thread(target=self._poll_csv, daemon=True)
        self._poll_thread.start()

        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

        self._status_thread = threading.Thread(target=self._status_loop, daemon=True)
        self._status_thread.start()

    # 🔥 NEW: real status (based on observed data, not iw)
    def _status_loop(self):
        if not self.on_status:
            return

        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        tick = 0

        while not self._stop_event.is_set():
            spin = spinner[tick % len(spinner)]

            if self.channel:
                msg = f"{spin} Locked on channel {self.channel} · scanning…"
            else:
                channels = sorted(
                    {ap.channel for ap in self.access_points.values() if ap.channel}
                )
                if channels:
                    ch_str = ", ".join(map(str, channels[:6]))
                    if len(channels) > 6:
                        ch_str += "..."
                    msg = f"{spin} Hopping · seen: {ch_str}"
                else:
                    msg = f"{spin} Hopping · scanning…"

            self.on_status(msg)
            tick += 1
            time.sleep(0.7)

    def _drain_stderr(self):
        if not self._proc or not self._proc.stderr:
            return

        for line in self._proc.stderr:
            print("STDERR:", line.strip())  # 🔥 force print
            if self.on_error:
                self.on_error(f"[airodump] {line.strip()}")

    def _poll_csv(self):
        csv_path = self._prefix + "-01.csv"

        print("CSV PATH:", csv_path)
        print("EXISTS:", os.path.exists(csv_path))

        while not self._stop_event.is_set():
            time.sleep(1)

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
        aps: list[AccessPoint] = []

        try:
            with open(path, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)

                headers = None

                for row in reader:
                    if not row:
                        continue

                    # Detect AP header
                    if row[0].strip().lower() == "bssid":
                        headers = [h.strip().lower() for h in row]
                        continue

                    # Stop at station section
                    if row[0].strip().lower().startswith("station mac"):
                        break

                    if not headers:
                        continue

                    # 🔥 Skip broken/incomplete rows safely
                    if len(row) < len(headers):
                        continue

                    data = dict(zip(headers, [c.strip() for c in row]))

                    bssid = data.get("bssid", "")
                    if not re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", bssid):
                        continue

                    ssid = data.get("essid", "")
                    hidden = not ssid or not ssid.strip() or "\x00" in ssid

                    def _int(k, d=0):
                        try:
                            return int(data.get(k, d))
                        except:
                            return d

                    aps.append(
                        AccessPoint(
                            bssid=bssid,
                            ssid="" if hidden else ssid,
                            channel=_int("channel"),
                            frequency="",
                            encryption=data.get("privacy", ""),
                            cipher=data.get("cipher", ""),
                            auth=data.get("authentication", ""),
                            power=_int("power", -100),
                            beacons=_int("# beacons"),
                            data_packets=_int("# iv"),
                            hidden=hidden,
                        )
                    )

        except Exception as e:
            if self.on_error:
                self.on_error(f"[parse] {e}")

        return aps

    def stop(self):
        self._stop_event.set()

        if self._proc:
            self._proc.terminate()
            self._proc.wait()

        for t in (self._poll_thread, self._stderr_thread, self._status_thread):
            if t:
                t.join(timeout=2)

        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)
