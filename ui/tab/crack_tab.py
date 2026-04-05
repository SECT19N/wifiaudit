"""
ui/tabs/crack_tab.py — Password cracking tab (aircrack-ng / hashcat toggle)
"""

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.cracker import CrackBackend, Cracker, CrackProgress


class CrackTab(QWidget):
    def __init__(self, shared: dict):
        super().__init__()
        self._shared = shared
        self._cracker: Cracker | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Backend selector
        backend_grp = QGroupBox("Cracking Backend")
        backend_grp.setObjectName("sectionGroup")
        bl = QHBoxLayout(backend_grp)

        self._aircrack_radio = QRadioButton("aircrack-ng  (CPU, .cap file)")
        self._aircrack_radio.setChecked(True)
        self._hashcat_radio = QRadioButton("hashcat  (GPU, .hc22000 file)")
        self._bg = QButtonGroup()
        self._bg.addButton(self._aircrack_radio, 0)
        self._bg.addButton(self._hashcat_radio, 1)
        self._aircrack_radio.toggled.connect(self._on_backend_changed)

        aircrack_note = QLabel("CPU-based. Works directly on .cap files.")
        aircrack_note.setObjectName("dimLabel")
        hashcat_note = QLabel(
            "GPU-accelerated. Requires hcxtools for conversion. Much faster."
        )
        hashcat_note.setObjectName("dimLabel")

        col1 = QVBoxLayout()
        col1.addWidget(self._aircrack_radio)
        col1.addWidget(aircrack_note)
        col2 = QVBoxLayout()
        col2.addWidget(self._hashcat_radio)
        col2.addWidget(hashcat_note)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setObjectName("separator")

        bl.addLayout(col1, 1)
        bl.addWidget(sep)
        bl.addLayout(col2, 1)
        layout.addWidget(backend_grp)

        # File inputs
        files_grp = QGroupBox("Input Files")
        files_grp.setObjectName("sectionGroup")
        fl = QVBoxLayout(files_grp)

        # Capture file
        cap_row = QHBoxLayout()
        self._cap_lbl = QLabel("Capture file (.cap / .hc22000):")
        self._cap_lbl.setObjectName("fieldLabel")
        self._cap_input = QLineEdit()
        self._cap_input.setObjectName("inlineInput")
        self._cap_input.setPlaceholderText("path/to/handshake.cap")
        self._cap_browse = QPushButton("Browse…")
        self._cap_browse.setObjectName("secondaryBtn")
        self._cap_browse.clicked.connect(self._browse_cap)
        cap_row.addWidget(self._cap_lbl)
        cap_row.addWidget(self._cap_input, 1)
        cap_row.addWidget(self._cap_browse)
        fl.addLayout(cap_row)

        # Wordlist
        wl_row = QHBoxLayout()
        wl_lbl = QLabel("Wordlist:")
        wl_lbl.setObjectName("fieldLabel")
        self._wl_input = QLineEdit()
        self._wl_input.setObjectName("inlineInput")
        self._wl_input.setPlaceholderText("/usr/share/wordlists/rockyou.txt")
        self._wl_input.setText("/usr/share/wordlists/rockyou.txt")
        self._wl_browse = QPushButton("Browse…")
        self._wl_browse.setObjectName("secondaryBtn")
        self._wl_browse.clicked.connect(self._browse_wordlist)
        wl_row.addWidget(wl_lbl)
        wl_row.addWidget(self._wl_input, 1)
        wl_row.addWidget(self._wl_browse)
        fl.addLayout(wl_row)

        # BSSID filter (aircrack only)
        bssid_row = QHBoxLayout()
        self._bssid_filter_lbl = QLabel("BSSID filter (optional):")
        self._bssid_filter_lbl.setObjectName("fieldLabel")
        self._bssid_filter = QLineEdit()
        self._bssid_filter.setObjectName("inlineInput")
        self._bssid_filter.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        bssid_row.addWidget(self._bssid_filter_lbl)
        bssid_row.addWidget(self._bssid_filter, 1)
        fl.addLayout(bssid_row)
        layout.addWidget(files_grp)

        # Start/Stop
        ctrl = QHBoxLayout()
        self._crack_btn = QPushButton("⬡  Start Cracking")
        self._crack_btn.setObjectName("primaryBtn")
        self._crack_btn.setMinimumWidth(180)
        self._crack_btn.clicked.connect(self._toggle_crack)
        self._result_lbl = QLabel("")
        self._result_lbl.setObjectName("resultLabel")
        ctrl.addWidget(self._crack_btn)
        ctrl.addSpacing(16)
        ctrl.addWidget(self._result_lbl)
        ctrl.addStretch()
        layout.addLayout(ctrl)

        # Stats row
        self._stats_frame = QFrame()
        self._stats_frame.setObjectName("statsBar")
        sf = QHBoxLayout(self._stats_frame)
        sf.setContentsMargins(12, 6, 12, 6)
        self._stat_kps = self._make_stat("Keys/sec", "—")
        self._stat_tested = self._make_stat("Keys tested", "0")
        self._stat_elapsed = self._make_stat("Elapsed", "0s")
        self._stat_eta = self._make_stat("ETA", "—")
        for s in [
            self._stat_kps,
            self._stat_tested,
            self._stat_elapsed,
            self._stat_eta,
        ]:
            sf.addWidget(s)
            sf.addSpacing(24)
        sf.addStretch()
        self._stats_frame.setVisible(False)
        layout.addWidget(self._stats_frame)

        # Progress bar (indeterminate)
        self._progress = QProgressBar()
        self._progress.setObjectName("captureProgress")
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(6)
        self._progress.setVisible(False)
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

        # Result banner (hidden until found)
        self._found_banner = QFrame()
        self._found_banner.setObjectName("successBanner")
        fb = QHBoxLayout(self._found_banner)
        fb.setContentsMargins(20, 12, 20, 12)
        self._found_icon = QLabel("🔓")
        self._found_password = QLabel("")
        self._found_password.setObjectName("foundPassword")
        fb.addWidget(self._found_icon)
        fb.addSpacing(12)
        fb.addWidget(self._found_password, 1)
        self._found_banner.setVisible(False)
        layout.addWidget(self._found_banner)

        # Timer for elapsed
        self._elapsed_timer = QTimer()
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._tick_elapsed)
        self._elapsed_seconds = 0

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

    def _on_backend_changed(self):
        is_aircrack = self._aircrack_radio.isChecked()
        self._bssid_filter_lbl.setVisible(is_aircrack)
        self._bssid_filter.setVisible(is_aircrack)

    def refresh_files(self):
        cap = self._shared.get("cap_file") or ""
        hc = self._shared.get("hc22000_file") or ""
        if self._aircrack_radio.isChecked() and cap:
            self._cap_input.setText(cap)
        elif self._hashcat_radio.isChecked() and hc:
            self._cap_input.setText(hc)
        elif cap:
            self._cap_input.setText(cap)

        bssid = self._shared.get("target_bssid") or ""
        if bssid:
            self._bssid_filter.setText(bssid)

    def _browse_cap(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select capture file", "", "Capture files (*.cap *.pcap *.hc22000)"
        )
        if path:
            self._cap_input.setText(path)

    def _browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select wordlist",
            "/usr/share/wordlists",
            "Text files (*.txt *.lst *)",
        )
        if path:
            self._wl_input.setText(path)

    def _toggle_crack(self):
        if self._cracker:
            self._cracker.stop()
            self._cracker = None
            self._set_cracking(False)
            self._log_msg("[*] Cracking stopped.")
            return

        cap_file = self._cap_input.text().strip()
        wordlist = self._wl_input.text().strip()

        if not cap_file:
            self._log_msg("[!] No capture file specified.")
            return
        if not wordlist:
            self._log_msg("[!] No wordlist specified.")
            return

        import os

        if not os.path.exists(cap_file):
            self._log_msg(f"[!] File not found: {cap_file}")
            return
        if not os.path.exists(wordlist):
            self._log_msg(f"[!] Wordlist not found: {wordlist}")
            return

        self._found_banner.setVisible(False)
        self._cracker = Cracker(
            on_progress=self._on_progress_threadsafe,
            on_done=self._on_done_threadsafe,
        )

        if self._aircrack_radio.isChecked():
            bssid = self._bssid_filter.text().strip()
            self._log_msg(f"[*] Starting aircrack-ng on {cap_file} with {wordlist}...")
            self._cracker.start_aircrack(cap_file, wordlist, bssid)
        else:
            self._log_msg(
                f"[*] Starting hashcat (mode 22000) on {cap_file} with {wordlist}..."
            )
            self._cracker.start_hashcat(cap_file, wordlist)

        self._set_cracking(True)

    def _set_cracking(self, active: bool):
        self._progress.setVisible(active)
        self._stats_frame.setVisible(active)
        if active:
            self._crack_btn.setText("■  Stop")
            self._crack_btn.setObjectName("dangerBtn")
            self._elapsed_seconds = 0
            self._elapsed_timer.start()
        else:
            self._crack_btn.setText("⬡  Start Cracking")
            self._crack_btn.setObjectName("primaryBtn")
            self._elapsed_timer.stop()
        self._crack_btn.style().unpolish(self._crack_btn)
        self._crack_btn.style().polish(self._crack_btn)

    def _tick_elapsed(self):
        self._elapsed_seconds += 1
        m, s = divmod(self._elapsed_seconds, 60)
        self._stat_elapsed._value_label.setText(f"{m}m {s}s" if m else f"{s}s")

    def _on_progress_threadsafe(self, p: CrackProgress):
        QTimer.singleShot(0, lambda: self._on_progress(p))

    def _on_done_threadsafe(self, p: CrackProgress):
        QTimer.singleShot(0, lambda: self._on_done(p))

    def _on_progress(self, p: CrackProgress):
        if p.keys_per_second >= 1_000_000:
            kps_str = f"{p.keys_per_second / 1_000_000:.1f} MH/s"
        elif p.keys_per_second >= 1_000:
            kps_str = f"{p.keys_per_second / 1_000:.1f} kH/s"
        else:
            kps_str = f"{p.keys_per_second:.0f} H/s"

        self._stat_kps._value_label.setText(kps_str)
        self._stat_tested._value_label.setText(f"{p.keys_tested:,}")
        if p.eta:
            self._stat_eta._value_label.setText(p.eta[:20])

    def _on_done(self, p: CrackProgress):
        self._cracker = None
        self._set_cracking(False)
        self._log_msg(f"\n[Result] {p.message}")
        if p.found:
            self._found_password.setText(f"Password found:  {p.password}")
            self._found_banner.setVisible(True)
            self._result_lbl.setText(f"✓ {p.password}")
            self._result_lbl.setStyleSheet(
                "color: #4ade80; font-weight: bold; font-size: 14px;"
            )
        else:
            self._result_lbl.setText("✗ Not found in wordlist")
            self._result_lbl.setStyleSheet("color: #f87171;")

    def _log_msg(self, msg: str):
        self._log.append(msg)
