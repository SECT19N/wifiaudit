import os
import re
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class WirelessAdapter:
    name: str
    phy: str
    driver: str
    chipset: str
    monitor_capable: bool
    in_monitor_mode: bool
    monitor_iface: Optional[str] = None
