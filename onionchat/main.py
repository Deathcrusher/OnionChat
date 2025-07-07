#!/usr/bin/env python3
"""Entry point and CLI for OnionChat."""
import argparse
import importlib
import sys

# Required and optional dependencies
REQUIRED_PKGS = ["torpy", "cryptography"]
OPTIONAL_PKGS = [
    "qrcode",
    "pyzbar",
    "opencv-python",
    "Pillow",
    "pyperclip",
]
DEPENDENCIES = REQUIRED_PKGS + OPTIONAL_PKGS


def check_dependencies():
    """Ensure mandatory packages are available."""
    missing = []
    for pkg in REQUIRED_PKGS:
        try:
            importlib.import_module(pkg.split("-")[0])
        except Exception:
            missing.append(pkg)
    if missing:
        deps = ", ".join(missing)
        raise RuntimeError(
            f"Missing required packages: {deps}. "
            "Install them with `pip install -r requirements.txt`."
        )

from onionchat.client_a import client_a_main
from onionchat.client_b import client_b_setup


def parse_args():
    parser = argparse.ArgumentParser(description="Secure Chat Messenger with GUI")
    parser.add_argument("mode", choices=["client_a", "client_b"], help="Run as client_a or client_b")
    parser.add_argument("--port", type=int, default=12345, help="Port for hidden service")
    parser.add_argument("--timeout", type=int, default=600, help="Session timeout in seconds")
    parser.add_argument("--padding", type=int, default=1024, help="Message padding length")
    parser.add_argument("--max-file-size", type=int, default=100, help="Maximum file size in MB")
    parser.add_argument(
        "--tor-impl",
        choices=["torpy", "stem"],
        default="stem",
        help="Tor implementation",
    )
    parser.add_argument("--onion", help="Client B onion address")
    parser.add_argument("--session", help="Client B session id")
    parser.add_argument("--key", help="Client B public key file")
    return parser.parse_args()


if __name__ == "__main__":
    check_dependencies()
    args = parse_args()
    if args.mode == "client_a":
        client_a_main(args)
    else:
        if args.onion and args.session and args.key:
            from onionchat import client_b as _client_b
            _client_b.client_b_main(args.onion, args.session, args.key, args)
        else:
            client_b_setup(args)
