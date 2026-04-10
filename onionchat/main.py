"""
OnionChat - Secure Anonymous One-Time Chat via Tor

Modern refactored version with:
- Async I/O for non-blocking operations
- Clean separation of concerns (Core, Transport, UI)
- Type-safe dataclasses for all protocols
- Proper error handling with error codes
- Secure memory management
- Modern Flet-based UI
"""

import asyncio
import argparse
import logging
import sys

from onionchat.core import SessionConfig
from onionchat.transport import TransportConfig
from onionchat.utils import setup_logging

logger = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="OnionChat - Secure Anonymous Chat via Tor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                  # Launch GUI
  %(prog)s --host           # Host a session
  %(prog)s --join QR_DATA   # Join existing session
  %(prog)s --cli            # Run in CLI mode
        """
    )
    
    parser.add_argument(
        '--host',
        action='store_true',
        help='Host a new chat session'
    )
    
    parser.add_argument(
        '--join',
        type=str,
        metavar='QR_DATA',
        help='Join existing session with QR data'
    )
    
    parser.add_argument(
        '--cli',
        action='store_true',
        help='Run in CLI mode instead of GUI'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='Port for hidden service (default: 8080)'
    )
    
    parser.add_argument(
        '--tor-control-port',
        type=int,
        default=9051,
        help='Tor control port (default: 9051)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '--log-file',
        type=str,
        help='Log to file instead of stdout'
    )
    
    return parser.parse_args()


async def run_cli_host():
    """Run CLI host mode."""
    from onionchat.core import ChatSession
    
    config = SessionConfig.generate()
    transport_config = TransportConfig(port=config.hidden_service_port)
    
    session = ChatSession(
        config=config,
        is_host=True,
        transport_config=transport_config
    )
    
    async def on_message(msg):
        print(f"\n[Remote]: {msg.content}")
        print("> ", end="", flush=True)
    
    async def on_status(status):
        print(f"[Status] {status}")
    
    session.set_message_callback(on_message)
    session.set_status_callback(on_status)
    
    await session.initialize()
    await session.start()
    
    credentials = session.get_credentials()
    print(f"\n=== Share this QR data with Client B ===")
    print(credentials.to_qr_data())
    print("==========================================\n")
    
    # Start input loop
    loop = asyncio.get_event_loop()
    while session._running:
        try:
            text = await loop.run_in_executor(None, input, "> ")
            if text.lower() == "exit":
                break
            await session.send_message(text)
        except EOFError:
            break
    
    await session.stop()


async def run_cli_join(qr_data: str):
    """Run CLI join mode."""
    from onionchat.core import SessionCredentials, ChatSession
    from onionchat.transport import TransportConfig
    
    try:
        credentials = SessionCredentials.from_qr_data(qr_data)
    except Exception as e:
        print(f"Invalid QR data: {e}")
        return
    
    config = SessionConfig.generate()
    transport_config = TransportConfig(
        host="localhost",  # Will be overridden by onion address
        port=config.hidden_service_port
    )
    
    session = ChatSession(
        config=config,
        is_host=False,
        transport_config=transport_config
    )
    
    async def on_message(msg):
        print(f"\n[Remote]: {msg.content}")
        print("> ", end="", flush=True)
    
    async def on_status(status):
        print(f"[Status] {status}")
    
    session.set_message_callback(on_message)
    session.set_status_callback(on_status)
    
    await session.initialize()
    # TODO: Implement proper join flow
    print("Join flow not yet implemented in CLI mode")
    await session.stop()


def run_gui():
    """Run the Flet GUI."""
    try:
        import flet as ft
        from onionchat.ui.flet_ui import main as ui_main
        
        ft.app(target=ui_main)
    except ImportError:
        print("Flet not installed. Install with: pip install flet")
        sys.exit(1)


def main():
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(level=log_level, log_file=args.log_file)
    
    logger.info("Starting OnionChat v2.0")
    
    try:
        if args.cli:
            if args.host:
                asyncio.run(run_cli_host())
            elif args.join:
                asyncio.run(run_cli_join(args.join))
            else:
                print("CLI mode requires --host or --join")
                sys.exit(1)
        else:
            run_gui()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
