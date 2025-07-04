#!/usr/bin/env python3
"""Entry point and CLI for OnionChat."""
import argparse
import subprocess
import sys

# Ensure dependencies are installed when running directly
DEPENDENCIES = [
    "torpy",
    "cryptography",
    "qrcode",
    "pyzbar",
    "opencv-python",
    "Pillow",
    "pyperclip",
]
for pkg in DEPENDENCIES:
    try:
        __import__(pkg.split("-")[0])
    except Exception:
        print(f"Installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

from client_a import client_a_main
from client_b import client_b_setup


def parse_args():
    parser = argparse.ArgumentParser(description="Secure Chat Messenger with GUI")
    parser.add_argument("mode", choices=["client_a", "client_b"], help="Run as client_a or client_b")
    parser.add_argument("--port", type=int, default=12345, help="Port for hidden service")
    parser.add_argument("--timeout", type=int, default=600, help="Session timeout in seconds")
    parser.add_argument("--padding", type=int, default=1024, help="Message padding length")
    parser.add_argument("--max-file-size", type=int, default=100, help="Maximum file size in MB")
    parser.add_argument("--tor-impl", choices=["torpy", "stem"], default="torpy", help="Tor implementation")
    parser.add_argument("--onion", help="Client B onion address")
    parser.add_argument("--session", help="Client B session id")
    parser.add_argument("--key", help="Client B public key file")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.mode == "client_a":
        client_a_main(args)
    else:
        if args.onion and args.session and args.key:
            client_b_main = __import__("client_b").client_b_main
            client_b_main(args.onion, args.session, args.key, args)
        else:
            client_b_setup(args)
