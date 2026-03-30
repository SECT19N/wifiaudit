from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from ui.tabs.adapter_tab import AdapterTab
from ui.tabs.capture_tab import CaptureTab
from ui.tabs.crack_tab import CrackTab
from ui.tabs.scanner_tab import ScannerTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WifiAudit - WPA2 Security Audit Tool")
        self.setMinimumSize(854, 480)
        self.resize(1280, 720)

        self._shared = {
            "monitor_iface": None,
            "target_bssid": None,
            "targed_ssid": None,
            "target_channel": None,
            "cap_file": None,
            "hc22000_file": None,
        }
        
        self._setup_ui()

    def _setup_ui(self):
        central = QWidget()

    def _on_adapter_changed(self, iface: str):
        self._shared["monitor_iface"] = iface

    def _on_target_selected(self, bssid: str, ssid: str, channel: int):
        self._shared["target_bssid"] = bssid
        self._shared["target_ssid"] = ssid
        self._shared["target_channel"] = channel

    def _on_capture_done(self, cap_file: str, hc22000_file: str):
        self._shared["cap_file"] = cap_file
        self._shared["hc22000_file"] = hc22000_file
