"""
ui/main_window.py — Main application window
"""

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

from ui.tab.adapter_tab import AdapterTab
from ui.tab.capture_tab import CaptureTab
from ui.tab.crack_tab import CrackTab
from ui.tab.scanner_tab import ScannerTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WifiAudit — WPA2 Security Audit Tool")
        self.setMinimumSize(1100, 750)
        self.resize(1200, 800)

        self._shared = {
            "monitor_iface": None,  # Active monitor-mode interface
            "target_bssid": None,
            "target_ssid": None,
            "target_channel": None,
            "cap_file": None,
            "hc22000_file": None,
        }

        self._setup_ui()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header bar ──
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(52)
        hlayout = QHBoxLayout(header)
        hlayout.setContentsMargins(20, 0, 20, 0)

        title_label = QLabel("⬡ WifiAudit")
        title_label.setObjectName("headerTitle")
        subtitle = QLabel("WPA2 Security Audit Suite  ·  Educational Use Only")
        subtitle.setObjectName("headerSubtitle")

        self._iface_badge = QLabel("No adapter in monitor mode")
        self._iface_badge.setObjectName("ifaceBadge")

        hlayout.addWidget(title_label)
        hlayout.addSpacing(16)
        hlayout.addWidget(subtitle)
        hlayout.addStretch()
        hlayout.addWidget(self._iface_badge)
        root.addWidget(header)

        # ── Tab widget ──
        self._tabs = QTabWidget()
        self._tabs.setObjectName("mainTabs")
        self._tabs.setDocumentMode(True)

        self._adapter_tab = AdapterTab(self._shared, self._on_adapter_changed)
        self._scanner_tab = ScannerTab(self._shared, self._on_target_selected)
        self._capture_tab = CaptureTab(self._shared, self._on_capture_done)
        self._crack_tab = CrackTab(self._shared)

        self._tabs.addTab(self._adapter_tab, "① Adapter")
        self._tabs.addTab(self._scanner_tab, "② Scan Networks")
        self._tabs.addTab(self._capture_tab, "③ Capture Handshake")
        self._tabs.addTab(self._crack_tab, "④ Crack Password")

        root.addWidget(self._tabs)

        # ── Status bar ──
        self._status = QStatusBar()
        self._status.setObjectName("mainStatus")
        self.setStatusBar(self._status)
        self._status.showMessage(
            "Ready — start by selecting a wireless adapter in tab ①"
        )

    def _on_adapter_changed(self, iface: str):
        self._shared["monitor_iface"] = iface
        if iface:
            self._iface_badge.setText(f"Monitor: {iface}")
            self._iface_badge.setProperty("active", "true")
            self._status.showMessage(
                f"Monitor mode active on {iface} — proceed to tab ②"
            )
        else:
            self._iface_badge.setText("No adapter in monitor mode")
            self._iface_badge.setProperty("active", "false")
        # Force style refresh
        self._iface_badge.style().unpolish(self._iface_badge)
        self._iface_badge.style().polish(self._iface_badge)

    def _on_target_selected(self, bssid: str, ssid: str, channel: int):
        self._shared["target_bssid"] = bssid
        self._shared["target_ssid"] = ssid
        self._shared["target_channel"] = channel
        self._capture_tab.refresh_target()
        self._status.showMessage(
            f"Target: {ssid or '<hidden>'} [{bssid}] ch{channel} — proceed to tab ③"
        )
        self._tabs.setCurrentIndex(2)

    def _on_capture_done(self, cap_file: str, hc22000_file: str):
        self._shared["cap_file"] = cap_file
        self._shared["hc22000_file"] = hc22000_file
        self._crack_tab.refresh_files()
        self._status.showMessage("Handshake captured — proceed to tab ④ to crack")
        self._tabs.setCurrentIndex(3)
