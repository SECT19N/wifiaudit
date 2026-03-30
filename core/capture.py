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
    cap_file: str
    hc22000_file: str
    message: str
