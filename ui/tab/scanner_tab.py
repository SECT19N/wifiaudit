"""
ui/tabs/scanner_tab.py — Passive network scanner with hidden SSID highlighting
"""

from typing import Callable

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.scanner import AccessPoint, Scanner


class ScannerTab(QWidget):
    target_selected = pyqtSignal(str, str, int)

    def __init__(self, shared: dict, on_target_selected: Callable):
        super().__init__()
        self._shared = shared
        self._on_target_selected = on_target_selected
        self._scanner: Scanner | None = None
        self._aps: list[AccessPoint] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Controls
        ctrl = QHBoxLayout()

        self._iface_label = QLabel("No monitor interface active")
        self._iface_label.setObjectName("dimLabel")

        ch_label = QLabel("Channel:")
        self._ch_combo = QComboBox()
        self._ch_combo.setObjectName("inlineCombo")
        self._ch_combo.addItem("All channels (hop)", 0)
        for ch in [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            36,
            40,
            44,
            48,
            52,
            56,
            60,
            64,
            100,
            104,
            108,
            112,
            116,
            120,
            124,
            128,
            132,
            136,
            140,
        ]:
            self._ch_combo.addItem(f"Ch {ch}", ch)

        self._scan_btn = QPushButton("▶  Start Scan")
        self._scan_btn.setObjectName("primaryBtn")
        self._scan_btn.clicked.connect(self._toggle_scan)

        self._target_btn = QPushButton("Set as Target  →")
        self._target_btn.setObjectName("accentBtn")
        self._target_btn.setEnabled(False)
        self._target_btn.clicked.connect(self._set_target)

        ctrl.addWidget(self._iface_label)
        ctrl.addStretch()
        ctrl.addWidget(ch_label)
        ctrl.addWidget(self._ch_combo)
        ctrl.addSpacing(8)
        ctrl.addWidget(self._scan_btn)
        ctrl.addSpacing(8)
        ctrl.addWidget(self._target_btn)
        layout.addLayout(ctrl)

        # Stats bar
        self._stats_bar = QFrame()
        self._stats_bar.setObjectName("statsBar")
        sb_layout = QHBoxLayout(self._stats_bar)
        sb_layout.setContentsMargins(12, 6, 12, 6)
        self._stat_total = self._make_stat("Networks", "0")
        self._stat_hidden = self._make_stat("Hidden SSIDs", "0")
        self._stat_wpa2 = self._make_stat("WPA2", "0")
        self._stat_open = self._make_stat("Open", "0")
        for s in [
            self._stat_total,
            self._stat_hidden,
            self._stat_wpa2,
            self._stat_open,
        ]:
            sb_layout.addWidget(s)
            sb_layout.addSpacing(24)
        sb_layout.addStretch()
        layout.addWidget(self._stats_bar)

        # Network table
        grp = QGroupBox("Detected Networks")
        grp.setObjectName("sectionGroup")
        glayout = QVBoxLayout(grp)

        self._table = QTableWidget()
        self._table.setObjectName("networkTable")
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels(
            [
                "BSSID",
                "SSID",
                "Ch",
                "Signal",
                "Encryption",
                "Clients",
                "Beacons",
                "Hidden",
            ]
        )
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.selectionModel().selectionChanged.connect(self._on_row_selected)
        glayout.addWidget(self._table)
        layout.addWidget(grp)

        # Detail panel
        detail_grp = QGroupBox("Selected Network Detail")
        detail_grp.setObjectName("sectionGroup")
        dl = QVBoxLayout(detail_grp)
        self._detail = QTextEdit()
        self._detail.setObjectName("logView")
        self._detail.setReadOnly(True)
        self._detail.setMaximumHeight(120)
        dl.addWidget(self._detail)
        layout.addWidget(detail_grp)

        # Hidden SSID explanation
        explain = QFrame()
        explain.setObjectName("warningBanner")
        el = QHBoxLayout(explain)
        el.setContentsMargins(16, 10, 16, 10)
        icon = QLabel("💡")
        text = QLabel(
            "Hidden SSIDs: A network with a blank SSID is still discoverable — it broadcasts "
            "beacon frames with an empty SSID field. The BSSID (MAC address) and channel are always visible. "
            "This demonstrates why 'hiding' an SSID is not a security measure."
        )
        text.setWordWrap(True)
        text.setObjectName("bannerText")
        el.addWidget(icon)
        el.addWidget(text, 1)
        layout.addWidget(explain)

    def _make_stat(self, label: str, value: str) -> QFrame:
        f = QFrame()
        f.setObjectName("statCard")
        l = QVBoxLayout(f)
        l.setContentsMargins(8, 4, 8, 4)
        l.setSpacing(0)
        v = QLabel(value)
        v.setObjectName("statValue")
        lb = QLabel(label)
        lb.setObjectName("statLabel")
        l.addWidget(v, alignment=Qt.AlignmentFlag.AlignCenter)
        l.addWidget(lb, alignment=Qt.AlignmentFlag.AlignCenter)
        f._value_label = v
        return f

    def _toggle_scan(self):
        iface = self._shared.get("monitor_iface")
        if not iface:
            self._detail.setPlainText(
                "[!] No monitor interface active. Enable monitor mode in tab ①."
            )
            return

        if self._scanner:
            self._scanner.stop()
            self._scanner = None
            self._scan_btn.setText("▶  Start Scan")
            self._scan_btn.setObjectName("primaryBtn")
            self._scan_btn.style().unpolish(self._scan_btn)
            self._scan_btn.style().polish(self._scan_btn)
        else:
            ch = self._ch_combo.currentData()
            self._scanner = Scanner(iface, self._on_scan_update, channel=ch)
            self._scanner.start()
            self._scan_btn.setText("■  Stop Scan")
            self._scan_btn.setObjectName("dangerBtn")
            self._scan_btn.style().unpolish(self._scan_btn)
            self._scan_btn.style().polish(self._scan_btn)
            self._iface_label.setText(f"Scanning on {iface}")

    def _on_scan_update(self, aps: list[AccessPoint]):
        # Must update UI from main thread
        QTimer.singleShot(0, lambda: self._update_table(aps))

    def _update_table(self, aps: list[AccessPoint]):
        self._aps = sorted(aps, key=lambda a: a.power, reverse=True)  # strongest first
        selected_bssid = None
        sel_row = self._table.currentRow()
        if 0 <= sel_row < len(self._aps):
            selected_bssid = (
                self._aps[sel_row].bssid if sel_row < self._table.rowCount() else None
            )

        self._table.setRowCount(0)
        for ap in self._aps:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setRowHeight(row, 28)

            def cell(txt, fg=None, bold=False):
                item = QTableWidgetItem(txt)
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if fg:
                    item.setForeground(QColor(fg))
                if bold:
                    f = item.font()
                    f.setBold(True)
                    item.setFont(f)
                return item

            self._table.setItem(row, 0, cell(ap.bssid))
            # SSID column — highlight hidden
            if ap.hidden:
                ssid_item = cell("⬡  <HIDDEN>", "#f59e0b", bold=True)
            else:
                ssid_item = cell(ap.ssid or "<empty>")
            self._table.setItem(row, 1, ssid_item)
            self._table.setItem(row, 2, cell(str(ap.channel)))

            # Signal
            sig_color = (
                "#4ade80"
                if ap.power > -60
                else ("#facc15" if ap.power > -75 else "#f87171")
            )
            self._table.setItem(row, 3, cell(f"{ap.power} dBm", sig_color))
            self._table.setItem(row, 4, cell(ap.encryption))
            self._table.setItem(row, 5, cell(str(len(ap.clients))))
            self._table.setItem(row, 6, cell(str(ap.beacons)))

            hidden_txt = "⬡ YES" if ap.hidden else "—"
            hidden_color = "#f59e0b" if ap.hidden else "#64748b"
            self._table.setItem(row, 7, cell(hidden_txt, hidden_color))

            # Restore selection
            if ap.bssid == selected_bssid:
                self._table.selectRow(row)

        # Update stats
        total = len(self._aps)
        hidden = sum(1 for a in self._aps if a.hidden)
        wpa2 = sum(1 for a in self._aps if "WPA2" in a.encryption or "WPA2" in a.cipher)
        open_ = sum(1 for a in self._aps if "OPN" in a.encryption or a.encryption == "")

        self._stat_total._value_label.setText(str(total))
        self._stat_hidden._value_label.setText(str(hidden))
        self._stat_wpa2._value_label.setText(str(wpa2))
        self._stat_open._value_label.setText(str(open_))

    def _on_row_selected(self):
        row = self._table.currentRow()
        if row < 0 or row >= len(self._aps):
            self._target_btn.setEnabled(False)
            return
        ap = self._aps[row]
        self._target_btn.setEnabled(True)

        clients_str = "\n    ".join(ap.clients) if ap.clients else "None detected"
        self._detail.setPlainText(
            f"BSSID:        {ap.bssid}\n"
            f"SSID:         {ap.display_ssid}\n"
            f"Channel:      {ap.channel}\n"
            f"Signal:       {ap.power} dBm  ({ap.signal_bar})\n"
            f"Encryption:   {ap.encryption}  Cipher: {ap.cipher}  Auth: {ap.auth}\n"
            f"Beacons:      {ap.beacons}\n"
            f"Data packets: {ap.data_packets}\n"
            f"Hidden SSID:  {'YES — SSID field is empty in beacon frames' if ap.hidden else 'No'}\n"
            f"Clients:\n    {clients_str}"
        )

    def _set_target(self):
        row = self._table.currentRow()
        if row < 0 or row >= len(self._aps):
            return
        ap = self._aps[row]
        self._on_target_selected(ap.bssid, ap.ssid, ap.channel)
