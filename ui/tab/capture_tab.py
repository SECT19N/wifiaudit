"""
ui/tabs/capture_tab.py — WPA2 handshake capture tab
"""

from typing import Callable

from PyQt6.QtCore import QObject, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.capture import CaptureResult, HandshakeCapturer


class CaptureTab(QWidget):
    def __init__(self, shared: dict, on_capture_done: Callable):
        super().__init__()
        self._shared = shared
        self._on_capture_done = on_capture_done
        self._capturer: HandshakeCapturer | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Target info
        target_grp = QGroupBox("Target Access Point")
        target_grp.setObjectName("sectionGroup")
        tl = QVBoxLayout(target_grp)

        self._target_frame = QFrame()
        self._target_frame.setObjectName("targetCard")
        tf = QHBoxLayout(self._target_frame)
        tf.setContentsMargins(16, 12, 16, 12)

        self._bssid_lbl = QLabel("BSSID: —")
        self._bssid_lbl.setObjectName("targetBSSID")
        self._ssid_lbl = QLabel("SSID: —")
        self._ssid_lbl.setObjectName("targetSSID")
        self._ch_lbl = QLabel("Ch: —")
        self._ch_lbl.setObjectName("targetCh")

        tf.addWidget(self._ssid_lbl)
        tf.addSpacing(24)
        tf.addWidget(self._bssid_lbl)
        tf.addSpacing(24)
        tf.addWidget(self._ch_lbl)
        tf.addStretch()
        tl.addWidget(self._target_frame)
        layout.addWidget(target_grp)

        # Options
        opts_grp = QGroupBox("Capture Options")
        opts_grp.setObjectName("sectionGroup")
        ol = QVBoxLayout(opts_grp)

        # Deauth row
        deauth_row = QHBoxLayout()
        self._deauth_check = QCheckBox("Send deauthentication frames")
        self._deauth_check.setChecked(True)
        self._deauth_check.setObjectName("optionCheck")
        deauth_note = QLabel(
            "Temporarily disconnects a client, forcing it to re-authenticate "
            "and exchange the 4-way handshake."
        )
        deauth_note.setObjectName("dimLabel")
        deauth_note.setWordWrap(True)
        deauth_row.addWidget(self._deauth_check)
        ol.addLayout(deauth_row)
        ol.addWidget(deauth_note)

        deauth_cnt_row = QHBoxLayout()
        cnt_lbl = QLabel("Deauth packet count:")
        cnt_lbl.setObjectName("dimLabel")
        self._deauth_count = QSpinBox()
        self._deauth_count.setObjectName("inlineSpinner")
        self._deauth_count.setRange(1, 100)
        self._deauth_count.setValue(5)
        self._deauth_count.setMaximumWidth(80)
        client_lbl = QLabel("Target client MAC (blank = broadcast):")
        client_lbl.setObjectName("dimLabel")
        self._client_mac = QLineEdit("FF:FF:FF:FF:FF:FF")
        self._client_mac.setObjectName("inlineInput")
        self._client_mac.setMaximumWidth(180)
        deauth_cnt_row.addWidget(cnt_lbl)
        deauth_cnt_row.addWidget(self._deauth_count)
        deauth_cnt_row.addSpacing(24)
        deauth_cnt_row.addWidget(client_lbl)
        deauth_cnt_row.addWidget(self._client_mac)
        deauth_cnt_row.addStretch()
        ol.addLayout(deauth_cnt_row)
        layout.addWidget(opts_grp)

        # Control
        ctrl = QHBoxLayout()
        self._start_btn = QPushButton("⬡  Start Capture")
        self._start_btn.setObjectName("primaryBtn")
        self._start_btn.setMinimumWidth(160)
        self._start_btn.clicked.connect(self._toggle_capture)

        self._status_lbl = QLabel("Ready")
        self._status_lbl.setObjectName("dimLabel")

        ctrl.addWidget(self._start_btn)
        ctrl.addSpacing(16)
        ctrl.addWidget(self._status_lbl)
        ctrl.addStretch()
        layout.addLayout(ctrl)

        # Progress pulse (indeterminate during capture)
        self._progress = QProgressBar()
        self._progress.setObjectName("captureProgress")
        self._progress.setRange(0, 0)  # Indeterminate
        self._progress.setVisible(False)
        self._progress.setFixedHeight(6)
        layout.addWidget(self._progress)

        # Log
        log_grp = QGroupBox("Live Output")
        log_grp.setObjectName("sectionGroup")
        ll = QVBoxLayout(log_grp)
        self._log = QTextEdit()
        self._log.setObjectName("logView")
        self._log.setReadOnly(True)
        ll.addWidget(self._log)
        layout.addWidget(log_grp)

        # Result
        result_grp = QGroupBox("Capture Result")
        result_grp.setObjectName("sectionGroup")
        rl = QHBoxLayout(result_grp)
        self._cap_path_lbl = QLabel("No capture file yet")
        self._cap_path_lbl.setObjectName("dimLabel")
        self._hc_path_lbl = QLabel("")
        self._hc_path_lbl.setObjectName("dimLabel")
        self._browse_btn = QPushButton("Browse .cap file…")
        self._browse_btn.setObjectName("secondaryBtn")
        self._browse_btn.clicked.connect(self._browse_cap)
        rl.addWidget(self._cap_path_lbl, 1)
        rl.addWidget(self._hc_path_lbl, 1)
        rl.addWidget(self._browse_btn)
        layout.addWidget(result_grp)

    def refresh_target(self):
        bssid = self._shared.get("target_bssid") or "—"
        ssid = self._shared.get("target_ssid") or "<hidden>"
        ch = self._shared.get("target_channel") or "—"
        self._bssid_lbl.setText(f"BSSID: {bssid}")
        self._ssid_lbl.setText(f"SSID: {ssid}")
        self._ch_lbl.setText(f"Ch: {ch}")

    def _toggle_capture(self):
        if self._capturer:
            self._capturer.stop()
            self._capturer = None
            self._start_btn.setText("⬡  Start Capture")
            self._start_btn.setObjectName("primaryBtn")
            self._start_btn.style().unpolish(self._start_btn)
            self._start_btn.style().polish(self._start_btn)
            self._progress.setVisible(False)
            self._status_lbl.setText("Stopped.")
            return

        iface = self._shared.get("monitor_iface")
        bssid = self._shared.get("target_bssid")
        channel = self._shared.get("target_channel")

        if not iface:
            self._log_msg("[!] No monitor interface. Enable monitor mode in tab ①.")
            return
        if not bssid:
            self._log_msg("[!] No target selected. Select a network in tab ②.")
            return

        client_mac = self._client_mac.text().strip() or "FF:FF:FF:FF:FF:FF"
        self._capturer = HandshakeCapturer(
            iface=iface,
            bssid=bssid,
            channel=channel or 6,
            on_log=self._on_log_threadsafe,
            on_handshake=self._on_handshake_threadsafe,
            client_mac=client_mac,
        )
        send_deauth = self._deauth_check.isChecked()
        count = self._deauth_count.value()
        self._capturer.start(send_deauth=send_deauth, deauth_count=count)

        self._start_btn.setText("■  Stop Capture")
        self._start_btn.setObjectName("dangerBtn")
        self._start_btn.style().unpolish(self._start_btn)
        self._start_btn.style().polish(self._start_btn)
        self._progress.setVisible(True)
        self._status_lbl.setText("Capturing…")

    def _on_log_threadsafe(self, msg: str):
        QTimer.singleShot(0, lambda: self._log_msg(msg))

    def _on_handshake_threadsafe(self, result: CaptureResult):
        QTimer.singleShot(0, lambda: self._on_handshake(result))

    def _on_handshake(self, result: CaptureResult):
        self._capturer = None
        self._start_btn.setText("⬡  Start Capture")
        self._start_btn.setObjectName("primaryBtn")
        self._start_btn.style().unpolish(self._start_btn)
        self._start_btn.style().polish(self._start_btn)
        self._progress.setVisible(False)

        if result.success:
            self._status_lbl.setText("✓ Handshake captured!")
            self._cap_path_lbl.setText(f".cap: {result.cap_file}")
            self._hc_path_lbl.setText(f"hc22000: {result.hc22000_file or 'N/A'}")
            self._on_capture_done(result.cap_file, result.hc22000_file)
        else:
            self._status_lbl.setText(f"✗ {result.message}")

    def _browse_cap(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select .cap file", "", "Capture files (*.cap *.pcap *.hc22000)"
        )
        if path:
            if path.endswith(".hc22000"):
                self._shared["hc22000_file"] = path
                self._hc_path_lbl.setText(f"hc22000: {path}")
            else:
                self._shared["cap_file"] = path
                self._cap_path_lbl.setText(f".cap: {path}")

    def _log_msg(self, msg: str):
        self._log.append(msg)
