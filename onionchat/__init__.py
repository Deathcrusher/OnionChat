"""
OnionChat - Secure Anonymous One-Time Chat via Tor Hidden Services

Modern refactored architecture with:
- Async I/O for non-blocking operations
- Clean separation of concerns (Core, Transport, UI)
- Type-safe dataclasses for all protocols
- Proper error handling with error codes
- Secure memory management
- Modern Flet-based UI
"""

__version__ = "2.0.0"
__author__ = "OnionChat Team"

from onionchat.core import (
    ChatSession,
    ChatMessage,
    SessionConfig,
    SessionCredentials,
)
from onionchat.transport import TransportConfig
from onionchat.utils import setup_logging

__all__ = [
    "ChatSession",
    "ChatMessage", 
    "SessionConfig",
    "SessionCredentials",
    "TransportConfig",
    "setup_logging",
]
