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
