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
