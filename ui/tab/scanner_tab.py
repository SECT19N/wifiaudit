"""
ui/tabs/scanner_tab.py — Passive network scanner with hidden SSID highlighting
"""

from typing import Callable, Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.scanner import AccessPoint, Scanner


class StatCard(QFrame):
    """A small labelled value card with a typed value_label attribute."""

    def __init__(self, label: str, value: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("statCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(0)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("statValue")
        lbl = QLabel(label)
        lbl.setObjectName("statLabel")
        layout.addWidget(self.value_label, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl, alignment=Qt.AlignmentFlag.AlignCenter)


class ScannerTab(QWidget):
    target_selected = pyqtSignal(str, str, int)

    def __init__(self, shared: dict, on_target_selected: Callable):
        super().__init__()
        self._shared = shared
        self._on_target_selected = on_target_selected
        self._scanner: Optional[Scanner] = None
        self._aps: list[AccessPoint] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # ── Controls ──
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

        # ── Live channel/band status bar ──
        self._status_frame = QFrame()
        self._status_frame.setObjectName("channelStatusBar")
        sf = QHBoxLayout(self._status_frame)
        sf.setContentsMargins(14, 7, 14, 7)
        self._channel_status_lbl = QLabel("Not scanning")
        self._channel_status_lbl.setObjectName("channelStatusLabel")
        sf.addWidget(self._channel_status_lbl)
        sf.addStretch()
        layout.addWidget(self._status_frame)

        # ── Stats row ──
        self._stats_bar = QFrame()
        self._stats_bar.setObjectName("statsBar")
        sb_layout = QHBoxLayout(self._stats_bar)
        sb_layout.setContentsMargins(12, 6, 12, 6)
        self._stat_total = StatCard("Networks", "0")
        self._stat_hidden = StatCard("Hidden SSIDs", "0")
        self._stat_wpa2 = StatCard("WPA2", "0")
        self._stat_open = StatCard("Open", "0")
        for card in (
            self._stat_total,
            self._stat_hidden,
            self._stat_wpa2,
            self._stat_open,
        ):
            sb_layout.addWidget(card)
            sb_layout.addSpacing(24)
        sb_layout.addStretch()
        layout.addWidget(self._stats_bar)

        # ── Network table ──
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
        hdr: Optional[QHeaderView] = self._table.horizontalHeader()
        if hdr is not None:
            hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            for col in range(2, 8):
                hdr.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)

        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)

        vhdr = self._table.verticalHeader()
        if vhdr is not None:
            vhdr.setVisible(False)

        sel_model = self._table.selectionModel()
        if sel_model is not None:
            sel_model.selectionChanged.connect(self._on_row_selected)

        glayout.addWidget(self._table)
        layout.addWidget(grp)

        # ── Detail panel ──
        detail_grp = QGroupBox("Selected Network Detail")
        detail_grp.setObjectName("sectionGroup")
        dl = QVBoxLayout(detail_grp)
        self._detail = QTextEdit()
        self._detail.setObjectName("logView")
        self._detail.setReadOnly(True)
        self._detail.setMaximumHeight(130)
        dl.addWidget(self._detail)
        layout.addWidget(detail_grp)

        # ── Hidden SSID explanation ──
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

    def _toggle_scan(self):
        iface = self._shared.get("monitor_iface")
        if not iface:
            self._detail.setPlainText(
                "[!] No monitor interface active. Enable monitor mode first."
            )
            return

        print("DEBUG iface:", iface)

        if self._scanner:
            self._scanner.stop()
            self._scanner = None

            self._scan_btn.setText("▶  Start Scan")
            self._scan_btn.setObjectName("primaryBtn")

            style = self._scan_btn.style()
            if style:
                style.unpolish(self._scan_btn)
                style.polish(self._scan_btn)

            # 🔥 Reset UI (important)
            self._table.setRowCount(0)
            self._aps.clear()
            self._target_btn.setEnabled(False)
            self._channel_status_lbl.setText("Stopped.")

            self._stat_total.value_label.setText("0")
            self._stat_hidden.value_label.setText("0")
            self._stat_wpa2.value_label.setText("0")
            self._stat_open.value_label.setText("0")

            return

        # 🔥 Ensure correct type (fix hidden bug)
        ch = self._ch_combo.currentData()
        try:
            ch = int(ch)
        except (TypeError, ValueError):
            ch = 0

        self._scanner = Scanner(
            iface=iface,
            on_update=self._on_scan_update,
            on_error=self._on_scan_error,
            on_status=self._on_scan_status,
            channel=ch,
        )

        self._scanner.start()

        self._scan_btn.setText("■  Stop Scan")
        self._scan_btn.setObjectName("dangerBtn")

        style = self._scan_btn.style()
        if style:
            style.unpolish(self._scan_btn)
            style.polish(self._scan_btn)

        if ch:
            self._iface_label.setText(f"{iface} · locked to channel {ch}")
        else:
            self._iface_label.setText(f"{iface} · hopping channels")

    def _on_scan_update(self, aps: list[AccessPoint]):
        QTimer.singleShot(0, lambda: self._update_table(aps))

    def _on_scan_status(self, msg: str):
        QTimer.singleShot(0, lambda: self._channel_status_lbl.setText(f"📡 {msg}"))

    def _on_scan_error(self, msg: str):
        QTimer.singleShot(0, lambda: self._detail.append(msg))

    def _update_table(self, aps: list[AccessPoint]):
        self._aps = sorted(aps, key=lambda a: a.power, reverse=True)

        # Preserve selection
        selected_bssid = None
        row = self._table.currentRow()
        if 0 <= row < len(self._aps):
            selected_bssid = self._aps[row].bssid

        self._table.setRowCount(len(self._aps))

        for row, ap in enumerate(self._aps):

            def cell(txt, color=None, bold=False):
                item = QTableWidgetItem(txt)
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                if color:
                    item.setForeground(QColor(color))

                if bold:
                    f = item.font()
                    f.setBold(True)
                    item.setFont(f)

                return item

            self._table.setItem(row, 0, cell(ap.bssid))

            if ap.hidden:
                self._table.setItem(row, 1, cell("⬡  <HIDDEN>", "#f59e0b", True))
            else:
                self._table.setItem(row, 1, cell(ap.ssid or "<empty>"))

            self._table.setItem(row, 2, cell(str(ap.channel)))

            sig_color = (
                "#4ade80"
                if ap.power > -60
                else "#facc15"
                if ap.power > -75
                else "#f87171"
            )
            self._table.setItem(row, 3, cell(f"{ap.power} dBm", sig_color))
            self._table.setItem(row, 4, cell(ap.encryption))
            self._table.setItem(row, 5, cell(str(len(ap.clients))))
            self._table.setItem(row, 6, cell(str(ap.beacons)))

            hidden_txt = "⬡ YES" if ap.hidden else "—"
            hidden_color = "#f59e0b" if ap.hidden else "#64748b"
            self._table.setItem(row, 7, cell(hidden_txt, hidden_color))

            if ap.bssid == selected_bssid:
                self._table.selectRow(row)

        # 🔥 Stats (unchanged logic, just cleaner)
        total = len(self._aps)
        hidden = sum(a.hidden for a in self._aps)
        wpa2 = sum("WPA2" in a.encryption or "WPA2" in a.cipher for a in self._aps)
        open_ = sum(a.encryption in ("", "OPN") for a in self._aps)

        self._stat_total.value_label.setText(str(total))
        self._stat_hidden.value_label.setText(str(hidden))
        self._stat_wpa2.value_label.setText(str(wpa2))
        self._stat_open.value_label.setText(str(open_))

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
