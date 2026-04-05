"""
core/cracker.py — WPA2 password cracking engine
Supports: aircrack-ng (CPU) and hashcat (GPU, hc22000)
"""

import re
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional


class CrackBackend(Enum):
    AIRCRACK = "aircrack-ng"
    HASHCAT = "hashcat"


@dataclass
class CrackProgress:
    backend: CrackBackend
    keys_tested: int
    keys_per_second: float
    current_key: str
    elapsed: float
    eta: str
    found: bool
    password: str
    message: str


class Cracker:
    """
    Runs aircrack-ng or hashcat against a wordlist in a background thread.
    Emits progress via on_progress(CrackProgress).
    """

    def __init__(
        self,
        on_progress: Callable[[CrackProgress], None],
        on_done: Callable[[CrackProgress], None],
    ):
        self.on_progress = on_progress
        self.on_done = on_done
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._start_time = 0.0

    def start_aircrack(self, cap_file: str, wordlist: str, bssid: str = ""):
        self._stop_event.clear()
        self._start_time = time.time()
        cmd = ["aircrack-ng", cap_file, "-w", wordlist]
        if bssid:
            cmd += ["-b", bssid]
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._thread = threading.Thread(target=self._stream_aircrack, daemon=True)
        self._thread.start()

    def _stream_aircrack(self):
        keys = 0
        kps = 0.0
        current = ""
        for line in self._proc.stdout:
            if self._stop_event.is_set():
                break
            line = line.rstrip()

            # KEY FOUND line
            m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", line)
            if m:
                password = m.group(1)
                progress = CrackProgress(
                    backend=CrackBackend.AIRCRACK,
                    keys_tested=keys,
                    keys_per_second=kps,
                    current_key=current,
                    elapsed=time.time() - self._start_time,
                    eta="",
                    found=True,
                    password=password,
                    message=f"Password found: {password}",
                )
                self.on_done(progress)
                return

            # Progress line: "3456 keys tested (1234.56 k/s)"
            m = re.search(r"(\d+)\s+keys tested.*?([\d.]+)\s*k/s", line, re.IGNORECASE)
            if m:
                keys = int(m.group(1))
                kps = float(m.group(2)) * 1000
                # Try to get current key
                km = re.search(r"Current passphrase:\s*(.+)", line)
                if km:
                    current = km.group(1).strip()
                self.on_progress(
                    CrackProgress(
                        backend=CrackBackend.AIRCRACK,
                        keys_tested=keys,
                        keys_per_second=kps,
                        current_key=current,
                        elapsed=time.time() - self._start_time,
                        eta="",
                        found=False,
                        password="",
                        message=line,
                    )
                )

            # KEY NOT FOUND
            if "KEY NOT FOUND" in line or "Passphrase not in dictionary" in line:
                progress = CrackProgress(
                    backend=CrackBackend.AIRCRACK,
                    keys_tested=keys,
                    keys_per_second=kps,
                    current_key=current,
                    elapsed=time.time() - self._start_time,
                    eta="",
                    found=False,
                    password="",
                    message="Password not found in wordlist.",
                )
                self.on_done(progress)
                return

        self._proc.wait()
        progress = CrackProgress(
            backend=CrackBackend.AIRCRACK,
            keys_tested=keys,
            keys_per_second=kps,
            current_key=current,
            elapsed=time.time() - self._start_time,
            eta="",
            found=False,
            password="",
            message="Cracking finished.",
        )
        self.on_done(progress)

    def start_hashcat(self, hc22000_file: str, wordlist: str):
        self._stop_event.clear()
        self._start_time = time.time()
        cmd = [
            "hashcat",
            "-m",
            "22000",
            hc22000_file,
            wordlist,
            "--status",
            "--status-timer=2",
            "--potfile-disable",
            "--force",
        ]
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._thread = threading.Thread(target=self._stream_hashcat, daemon=True)
        self._thread.start()

    def _stream_hashcat(self):
        keys = 0
        kps = 0.0
        eta = ""
        current = ""
        password = ""

        for line in self._proc.stdout:
            if self._stop_event.is_set():
                break
            line = line.rstrip()

            # Speed
            m = re.search(r"Speed.*?:\s*([\d.]+)\s*(H|kH|MH|GH)/s", line)
            if m:
                val = float(m.group(1))
                unit = m.group(2)
                mult = {"H": 1, "kH": 1e3, "MH": 1e6, "GH": 1e9}.get(unit, 1)
                kps = val * mult

            # Progress
            m = re.search(r"Progress.*?:\s*(\d+)/(\d+)", line)
            if m:
                keys = int(m.group(1))

            # ETA
            m = re.search(r"Time\.Estimated.*?:\s*(.+)", line)
            if m:
                eta = m.group(1).strip()

            # Cracked
            if "Cracked" in line or "Status" in line:
                pass  # status update handled below

            # Result line: hash:password
            # hashcat outputs "hash:password" when found
            if re.match(
                r"^[0-9a-f*]+:[0-9a-f*]+:[0-9a-f*]+:[0-9a-f*]+:[0-9a-f*]+:(.+)$", line
            ):
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    password = parts[1]

            # Status: Cracked
            if "Status" in line and "Cracked" in line:
                prog = CrackProgress(
                    backend=CrackBackend.HASHCAT,
                    keys_tested=keys,
                    keys_per_second=kps,
                    current_key=current,
                    elapsed=time.time() - self._start_time,
                    eta=eta,
                    found=True,
                    password=password,
                    message=f"Password found: {password}",
                )
                self.on_done(prog)
                return

            # Status: Exhausted
            if "Status" in line and "Exhausted" in line:
                prog = CrackProgress(
                    backend=CrackBackend.HASHCAT,
                    keys_tested=keys,
                    keys_per_second=kps,
                    current_key=current,
                    elapsed=time.time() - self._start_time,
                    eta=eta,
                    found=False,
                    password="",
                    message="Password not found in wordlist.",
                )
                self.on_done(prog)
                return

            if kps > 0 or keys > 0:
                self.on_progress(
                    CrackProgress(
                        backend=CrackBackend.HASHCAT,
                        keys_tested=keys,
                        keys_per_second=kps,
                        current_key=current,
                        elapsed=time.time() - self._start_time,
                        eta=eta,
                        found=False,
                        password="",
                        message=line,
                    )
                )

        self._proc.wait()
        rc = self._proc.returncode
        found = rc == 0
        prog = CrackProgress(
            backend=CrackBackend.HASHCAT,
            keys_tested=keys,
            keys_per_second=kps,
            current_key=current,
            elapsed=time.time() - self._start_time,
            eta=eta,
            found=found,
            password=password,
            message="Cracking finished."
            if not found
            else f"Password found: {password}",
        )
        self.on_done(prog)

    def stop(self):
        self._stop_event.set()
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
