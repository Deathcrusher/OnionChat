"""Entry script for OnionChat Client B."""
import argparse
from client_b import client_b_main, client_b_setup


def parse_args(argv=None):
    """Parse CLI arguments for Client B."""
    parser = argparse.ArgumentParser(description="Run OnionChat Client B")
    parser.add_argument("--onion", help="Onion address")
    parser.add_argument("--session", help="Session ID")
    parser.add_argument("--key", help="Public key file")
    parser.add_argument("--padding", type=int, default=1024, help="Message padding length")
    parser.add_argument("--max-file-size", type=int, default=100, help="Maximum file size in MB")
    parser.add_argument("--tor-impl", choices=["torpy", "stem"], default="torpy", help="Tor implementation")
    return parser.parse_args(argv)


def main(argv=None):
    """Entry point for the ``client-b`` console script."""
    args = parse_args(argv)
    if args.onion and args.session and args.key:
        client_b_main(args.onion, args.session, args.key, args)
    else:
        client_b_setup(args)


if __name__ == "__main__":
    args = parse_args()
    if args.onion and args.session and args.key:
        client_b_main(args.onion, args.session, args.key, args)
    else:
        client_b_setup(args)
