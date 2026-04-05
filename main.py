"""
WifiAudit — Educational WPA2 Audit Tool
For authorized penetration testing and coursework only.
"""

import os
import sys

# Warn early if not root
if os.geteuid() != 0:
    print("[!] WifiAudit must be run as root (sudo python3 main.py)")
    sys.exit(1)

from PyQt6.QtGui import QFont, QFontDatabase
from PyQt6.QtWidgets import QApplication

from ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("WifiAudit")
    app.setOrganizationName("InfoSec Course")

    # Load stylesheet
    qss_path = os.path.join(os.path.dirname(__file__), "ui", "style.qss")
    if os.path.exists(qss_path):
        with open(qss_path) as f:
            app.setStyleSheet(f.read())

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
