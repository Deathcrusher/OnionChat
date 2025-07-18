"""Entry script for OnionChat Client A."""

import argparse
from onionchat.client_a import client_a_main
from onionchat.main import check_dependencies


def parse_args(argv=None):
    """Parse CLI arguments for Client A."""
    parser = argparse.ArgumentParser(description="Run OnionChat Client A")
    parser.add_argument(
        "--port", type=int, default=12345, help="Port for hidden service"
    )
    parser.add_argument(
        "--timeout", type=int, default=600, help="Session timeout in seconds"
    )
    parser.add_argument(
        "--padding", type=int, default=1024, help="Message padding length"
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=100,
        help="Maximum file size in MB",
    )
    parser.add_argument(
        "--tor-impl",
        choices=["torpy", "stem"],
        default="stem",
        help="Tor implementation",
    )
    return parser.parse_args(argv)


def main(argv=None):
    """Entry point for the ``client-a`` console script."""
    check_dependencies()
    args = parse_args(argv)
    client_a_main(args)


if __name__ == "__main__":
    check_dependencies()
    args = parse_args()
    client_a_main(args)
