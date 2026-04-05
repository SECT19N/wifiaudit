"""
ui/tabs/adapter_tab.py — Adapter selection and monitor mode management
"""

from typing import Callable

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.adapter import (
    WirelessAdapter,
    disable_monitor_mode,
    enable_monitor_mode,
    list_interfaces,
)


class AdapterWorker(QObject):
    finished = pyqtSignal(bool, str)  # success, iface/message

    def __init__(self, iface: str, enable: bool):
        super().__init__()
        self.iface = iface
        self.enable = enable

    def run(self):
        if self.enable:
            ok, result = enable_monitor_mode(self.iface)
        else:
            ok, result = disable_monitor_mode(self.iface)
        self.finished.emit(ok, result)


class AdapterTab(QWidget):
    def __init__(self, shared: dict, on_adapter_changed: Callable):
        super().__init__()
        self._shared = shared
        self._on_adapter_changed = on_adapter_changed
        self._adapters: list[WirelessAdapter] = []
        self._selected_iface: str = ""
        self._monitor_iface: str = ""
        self._worker_thread: QThread | None = None
        self._setup_ui()
        self._refresh_adapters()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Info banner
        banner = QFrame()
        banner.setObjectName("infoBanner")
        bl = QHBoxLayout(banner)
        bl.setContentsMargins(16, 10, 16, 10)
        icon = QLabel("ℹ")
        icon.setObjectName("bannerIcon")
        text = QLabel(
            "WifiAudit requires a wireless adapter supporting monitor mode. "
            "Enable monitor mode below — this will pause NetworkManager temporarily."
        )
        text.setWordWrap(True)
        text.setObjectName("bannerText")
        bl.addWidget(icon)
        bl.addWidget(text, 1)
        layout.addWidget(banner)

        # Adapter table
        grp = QGroupBox("Detected Wireless Interfaces")
        grp.setObjectName("sectionGroup")
        glayout = QVBoxLayout(grp)

        self._table = QTableWidget()
        self._table.setObjectName("adapterTable")
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(
            ["Interface", "PHY", "Driver", "Monitor Capable", "Current Mode"]
        )
        self._table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.selectionModel().selectionChanged.connect(self._on_row_selected)
        glayout.addWidget(self._table)
        layout.addWidget(grp)

        # Control row
        ctrl = QHBoxLayout()
        self._refresh_btn = QPushButton("⟳  Refresh Interfaces")
        self._refresh_btn.setObjectName("secondaryBtn")
        self._refresh_btn.clicked.connect(self._refresh_adapters)

        self._monitor_btn = QPushButton("Enable Monitor Mode")
        self._monitor_btn.setObjectName("primaryBtn")
        self._monitor_btn.setEnabled(False)
        self._monitor_btn.clicked.connect(self._toggle_monitor)

        self._selected_label = QLabel("No interface selected")
        self._selected_label.setObjectName("dimLabel")

        ctrl.addWidget(self._refresh_btn)
        ctrl.addStretch()
        ctrl.addWidget(self._selected_label)
        ctrl.addSpacing(12)
        ctrl.addWidget(self._monitor_btn)
        layout.addLayout(ctrl)

        # Log
        log_grp = QGroupBox("Output")
        log_grp.setObjectName("sectionGroup")
        ll = QVBoxLayout(log_grp)
        self._log = QTextEdit()
        self._log.setObjectName("logView")
        self._log.setReadOnly(True)
        self._log.setMaximumHeight(160)
        ll.addWidget(self._log)
        layout.addWidget(log_grp)
        layout.addStretch()

    def _refresh_adapters(self):
        self._adapters = list_interfaces()
        self._table.setRowCount(0)
        for ap in self._adapters:
            row = self._table.rowCount()
            self._table.insertRow(row)

            def cell(txt, color=None):
                item = QTableWidgetItem(txt)
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if color:
                    item.setForeground(QColor(color))
                return item

            self._table.setItem(row, 0, cell(ap.name))
            self._table.setItem(row, 1, cell(ap.phy))
            self._table.setItem(row, 2, cell(ap.driver))

            capable = "✓ Yes" if ap.monitor_capable else "✗ No"
            cap_color = "#4ade80" if ap.monitor_capable else "#f87171"
            self._table.setItem(row, 3, cell(capable, cap_color))

            mode = "Monitor" if ap.in_monitor_mode else "Managed"
            mode_color = "#facc15" if ap.in_monitor_mode else "#94a3b8"
            self._table.setItem(row, 4, cell(mode, mode_color))

        if not self._adapters:
            self._log_msg(
                "[!] No wireless interfaces found. Is a Wi-Fi adapter connected?"
            )
        else:
            self._log_msg(f"[✓] Found {len(self._adapters)} wireless interface(s).")

    def _on_row_selected(self):
        rows = self._table.selectedItems()
        if not rows:
            self._monitor_btn.setEnabled(False)
            return
        row = self._table.currentRow()
        if row < 0 or row >= len(self._adapters):
            return
        ap = self._adapters[row]
        self._selected_iface = ap.name
        self._selected_label.setText(f"Selected: {ap.name}")

        if ap.in_monitor_mode:
            self._monitor_btn.setText("Disable Monitor Mode")
            self._monitor_btn.setObjectName("dangerBtn")
        else:
            self._monitor_btn.setText("Enable Monitor Mode")
            self._monitor_btn.setObjectName("primaryBtn")
        self._monitor_btn.style().unpolish(self._monitor_btn)
        self._monitor_btn.style().polish(self._monitor_btn)
        self._monitor_btn.setEnabled(ap.monitor_capable)

    def _toggle_monitor(self):
        if not self._selected_iface:
            return
        row = self._table.currentRow()
        if row < 0 or row >= len(self._adapters):
            return
        ap = self._adapters[row]
        enabling = not ap.in_monitor_mode

        self._monitor_btn.setEnabled(False)
        self._refresh_btn.setEnabled(False)
        action = "Enabling" if enabling else "Disabling"
        self._log_msg(f"[*] {action} monitor mode on {self._selected_iface}...")
        self._log_msg(
            f"[*] Running: airmon-ng check kill && airmon-ng start {self._selected_iface}"
        )

        # Store on self to prevent garbage collection before thread finishes
        self._worker = AdapterWorker(self._selected_iface, enabling)
        self._worker_thread = QThread()
        self._worker.moveToThread(self._worker_thread)
        self._worker.finished.connect(
            lambda ok, msg: self._on_monitor_done(ok, msg, enabling)
        )
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker_thread.finished.connect(self._worker.deleteLater)
        self._worker_thread.finished.connect(self._worker_thread.deleteLater)
        self._worker_thread.started.connect(self._worker.run)
        self._worker_thread.start()

    def _on_monitor_done(self, ok: bool, result: str, was_enabling: bool):
        self._monitor_btn.setEnabled(True)
        self._refresh_btn.setEnabled(True)
        if ok:
            if was_enabling:
                self._monitor_iface = result
                self._log_msg(f"[✓] Monitor mode enabled → interface: {result}")
                # Double-check by re-reading iw dev
                import subprocess

                iw_out = subprocess.run(
                    ["iw", "dev"], capture_output=True, text=True
                ).stdout
                self._log_msg(f"[i] iw dev output:\n{iw_out.strip()}")
                self._on_adapter_changed(result)
            else:
                self._log_msg(f"[✓] Monitor mode disabled. {result}")
                self._on_adapter_changed("")
        else:
            self._log_msg(f"[✗] Failed: {result}")
            # Still dump iw dev so we can see actual state
            import subprocess

            iw_out = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True
            ).stdout
            self._log_msg(f"[i] iw dev output:\n{iw_out.strip()}")
        self._refresh_adapters()

    def _log_msg(self, msg: str):
        self._log.append(msg)
