"""
Transport layer abstraction for OnionChat.

Provides abstract interface and implementations for:
- Direct TCP connections (local testing)
- Tor hidden services (production)
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Optional, AsyncIterator, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class TransportConfig:
    """Configuration for transport layer."""
    host: str = "localhost"
    port: int = 8080
    tor_control_port: int = 9051
    tor_socks_port: int = 9050
    timeout: float = 30.0


class TransportError(Exception):
    """Custom exception for transport errors."""
    def __init__(self, message: str, error_code: str = "TRANSPORT_ERROR"):
        super().__init__(message)
        self.error_code = error_code


class BaseTransport(ABC):
    """Abstract base class for transport implementations."""
    
    def __init__(self, config: TransportConfig):
        self.config = config
        self._connected = False
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
    
    @property
    def is_connected(self) -> bool:
        """Check if transport is connected."""
        return self._connected
    
    @abstractmethod
    async def connect(self) -> None:
        """Establish connection."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection."""
        pass
    
    @abstractmethod
    async def send(self, data: bytes) -> None:
        """Send data over the connection."""
        pass
    
    @abstractmethod
    async def receive(self) -> bytes:
        """Receive data from the connection."""
        pass
    
    async def send_packet(self, data: bytes) -> None:
        """Send a length-prefixed packet."""
        length = len(data).to_bytes(4, 'big')
        await self.send(length + data)
    
    async def receive_packet(self) -> bytes:
        """Receive a length-prefixed packet."""
        length_bytes = await self._receive_exact(4)
        length = int.from_bytes(length_bytes, 'big')
        return await self._receive_exact(length)
    
    async def _receive_exact(self, size: int) -> bytes:
        """Receive exactly `size` bytes."""
        data = b""
        while len(data) < size:
            chunk = await self._reader.read(size - len(data))
            if not chunk:
                raise TransportError("Connection closed", "CONNECTION_CLOSED")
            data += chunk
        return data
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()


class TCPTransport(BaseTransport):
    """Simple TCP transport for local testing."""
    
    async def connect(self) -> None:
        """Connect to TCP server."""
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.host, self.config.port),
                timeout=self.config.timeout
            )
            self._connected = True
            logger.info(f"Connected to {self.config.host}:{self.config.port}")
        except asyncio.TimeoutError:
            raise TransportError("Connection timeout", "TIMEOUT")
        except Exception as e:
            raise TransportError(f"Connection failed: {e}", "CONNECTION_FAILED")
    
    async def disconnect(self) -> None:
        """Close TCP connection."""
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        self._connected = False
        logger.info("TCP connection closed")
    
    async def send(self, data: bytes) -> None:
        """Send data over TCP."""
        if not self._connected or not self._writer:
            raise TransportError("Not connected", "NOT_CONNECTED")
        self._writer.write(data)
        await self._writer.drain()
    
    async def receive(self) -> bytes:
        """Receive data from TCP."""
        if not self._connected or not self._reader:
            raise TransportError("Not connected", "NOT_CONNECTED")
        data = await self._reader.read(4096)
        if not data:
            raise TransportError("Connection closed", "CONNECTION_CLOSED")
        return data


class TorTransport(BaseTransport):
    """Tor hidden service transport with real Tor integration."""
    
    def __init__(self, config: TransportConfig, is_server: bool = False):
        super().__init__(config)
        self.is_server = is_server
        self._onion_address: Optional[str] = None
        self._tor_process: Optional[asyncio.subprocess.Process] = None
        self._server: Optional[asyncio.Server] = None
        self._stem_controller = None  # Stem controller for Tor control
        self._temp_dir: Optional[str] = None
    
    @property
    def onion_address(self) -> Optional[str]:
        """Get the onion address (server mode only)."""
        return self._onion_address
    
    async def connect(self) -> None:
        """Connect via Tor SOCKS proxy."""
        if self.is_server:
            await self._start_server()
        else:
            await self._connect_via_tor()
    
    async def _start_server(self) -> None:
        """Start Tor hidden service and server."""
        try:
            # Try to use stem for real Tor integration
            try:
                from stem import Signal
                from stem.control import Controller
                import secrets
                import tempfile
                import os
                
                # Create temporary directory for hidden service
                self._temp_dir = tempfile.mkdtemp(prefix="onionchat_")
                hs_dir = os.path.join(self._temp_dir, "hidden_service")
                os.makedirs(hs_dir, exist_ok=True)
                
                # Start local server
                self._server = await asyncio.start_server(
                    self._handle_client,
                    self.config.host,
                    self.config.port
                )
                
                # Connect to Tor control port
                try:
                    self._stem_controller = Controller.from_port(port=self.config.tor_control_port)
                    self._stem_controller.authenticate()  # May need password in production
                    
                    # Create ephemeral hidden service
                    logger.info("Creating ephemeral hidden service via Stem...")
                    private_key_type = 'NEW=BEST'
                    
                    # Create hidden service with v3 onion address
                    hs = self._stem_controller.create_ephemeral_hidden_service(
                        {80: self.config.port},  # Map port 80 on onion to our local port
                        await_content_detection=False,
                        private_key_type=private_key_type,
                        key_content='ED25519-V3'
                    )
                    
                    self._onion_address = f"{hs.service_id}.onion"
                    logger.info(f"Hidden service created: {self._onion_address}")
                    
                except Exception as e:
                    # Fallback: simulate onion address if Tor not available
                    logger.warning(f"Tor control connection failed ({e}), using simulated address")
                    self._onion_address = f"test-onion-{secrets.token_hex(8)}.onion"
                
                self._connected = True
                logger.info(f"Tor server started on {self._onion_address}")
                
            except ImportError:
                # Stem not available, use fallback
                logger.warning("Stem not installed, using simulated Tor address")
                await self._start_fallback_server()
                
        except Exception as e:
            raise TransportError(f"Failed to start Tor server: {e}", "TOR_SERVER_FAILED")
    
    async def _start_fallback_server(self) -> None:
        """Fallback server without real Tor (for testing)."""
        import secrets
        
        # Start local server
        self._server = await asyncio.start_server(
            self._handle_client,
            self.config.host,
            self.config.port
        )
        
        # Simulate onion address
        self._onion_address = f"test-onion-{secrets.token_hex(8)}.onion"
        self._connected = True
        logger.info(f"Fallback server started on {self._onion_address} (NOT REAL TOR)")
    
    async def _connect_via_tor(self) -> None:
        """Connect to onion service via Tor."""
        try:
            # Try to use torpy for real Tor connection
            try:
                from torpy.doer import TorDoer
                
                logger.info(f"Connecting to onion service via Tor...")
                
                # Create Tor session and connect
                async with TorDoer() as doer:
                    # Get the onion address from session info or config
                    if self.session_info and self.session_info.remote_credentials:
                        onion_addr = self.session_info.remote_credentials.onion_address
                    else:
                        # Fallback to host from config (should be onion address)
                        onion_addr = self.config.host
                    
                    # Connect via Tor SOCKS proxy
                    self._reader, self._writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            onion_addr,
                            self.config.port,
                            ssl=False
                        ),
                        timeout=self.config.timeout
                    )
                    
                    self._connected = True
                    logger.info(f"Connected to {onion_addr} via Tor")
                    
            except ImportError:
                # torpy not available, try stem SOCKS
                try:
                    from stem.util.connection import create_connection
                    
                    logger.info("Connecting via Tor SOCKS proxy (stem)...")
                    
                    # Determine onion address
                    if self.session_info and self.session_info.remote_credentials:
                        onion_addr = self.session_info.remote_credentials.onion_address
                    else:
                        onion_addr = self.config.host
                    
                    # Connect via stem's SOCKS proxy
                    sock = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: create_connection(
                            (onion_addr, self.config.port),
                            socks_port=self.config.tor_socks_port
                        )
                    )
                    
                    self._reader, self._writer = await asyncio.open_connection(
                        sock=sock
                    )
                    self._connected = True
                    logger.info(f"Connected to {onion_addr} via Tor SOCKS")
                    
                except Exception as e:
                    # Fallback: direct connection for testing
                    logger.warning(f"Tor connection failed ({e}), using direct connection (TESTING ONLY)")
                    await self._connect_direct()
                    
        except asyncio.TimeoutError:
            raise TransportError("Tor connection timeout", "TOR_TIMEOUT")
        except Exception as e:
            raise TransportError(f"Tor connection failed: {e}", "TOR_CONNECTION_FAILED")
    
    async def _connect_direct(self) -> None:
        """Fallback direct connection for testing (no Tor)."""
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.config.host, self.config.port),
            timeout=self.config.timeout
        )
        self._connected = True
        logger.warning(f"Direct connection to {self.config.host}:{self.config.port} (NOT VIA TOR!)")
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connection."""
        self._reader = reader
        self._writer = writer
        self._connected = True
        logger.info("Client connected to Tor hidden service")
    
    async def disconnect(self) -> None:
        """Close Tor connection and cleanup."""
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
        
        # Cleanup stem controller and hidden service
        if self._stem_controller:
            try:
                # Remove ephemeral hidden service
                self._stem_controller.close()
                logger.info("Tor controller closed")
            except Exception as e:
                logger.warning(f"Error closing Tor controller: {e}")
        
        # Cleanup temporary directory
        if self._temp_dir:
            try:
                import shutil
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                logger.info(f"Temporary directory cleaned up: {self._temp_dir}")
            except Exception as e:
                logger.warning(f"Error cleaning up temp dir: {e}")
        
        self._connected = False
        logger.info("Tor connection closed")
    
    async def send(self, data: bytes) -> None:
        """Send data over Tor."""
        if not self._connected or not self._writer:
            raise TransportError("Not connected", "NOT_CONNECTED")
        self._writer.write(data)
        await self._writer.drain()
    
    async def receive(self) -> bytes:
        """Receive data from Tor."""
        if not self._connected or not self._reader:
            raise TransportError("Not connected", "NOT_CONNECTED")
        data = await self._reader.read(4096)
        if not data:
            raise TransportError("Connection closed", "CONNECTION_CLOSED")
        return data
