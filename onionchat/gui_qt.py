from __future__ import annotations

import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QTextEdit, QLineEdit, QPushButton
)


class ChatWindow(QWidget):
    """A simple PyQt6 chat window."""

    def __init__(self, send_callback=None):
        super().__init__()
        self.send_callback = send_callback
        self.setWindowTitle("OnionChat (Qt)")
        self.resize(600, 400)

        layout = QVBoxLayout(self)
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)

        self.message_entry = QLineEdit()
        layout.addWidget(self.message_entry)

        send_btn = QPushButton("Send")
        layout.addWidget(send_btn)

        send_btn.clicked.connect(self._on_send)
        self.message_entry.returnPressed.connect(self._on_send)

    def append_chat(self, author: str, text: str) -> None:
        self.chat_display.append(f"<b>{author}:</b> {text}")

    def _on_send(self) -> None:
        text = self.message_entry.text().strip()
        if not text:
            return
        if self.send_callback:
            self.send_callback(text)
        self.append_chat("You", text)
        self.message_entry.clear()


def main() -> None:
    """Launch a basic PyQt6 chat window."""
    app = QApplication(sys.argv)
    win = ChatWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":  # pragma: no cover - manual execution
    main()
