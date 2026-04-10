"""
Utility functions for OnionChat.

Includes:
- QR code generation
- Logging setup
- Memory utilities
"""

import io
import base64
import logging
import sys
from pathlib import Path

import qrcode


def setup_logging(level: int = logging.INFO, log_file: str = None):
    """Setup logging configuration."""
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers,
    )
    
    # Reduce noise from external libraries
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('cryptography').setLevel(logging.WARNING)


def generate_qr_image(data: str, size: int = 10) -> str:
    """
    Generate QR code image and return as base64 data URI.
    
    Args:
        data: Data to encode in QR code
        size: Size of each box in pixels
    
    Returns:
        Base64-encoded PNG data URI
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=size,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    img_bytes = buffer.read()
    img_base64 = base64.b64encode(img_bytes).decode('utf-8')
    
    return f"data:image/png;base64,{img_base64}"


def format_bytes(size: int) -> str:
    """Format byte size to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    return Path(filename).name


__all__ = [
    "setup_logging",
    "generate_qr_image",
    "format_bytes",
    "sanitize_filename",
]
