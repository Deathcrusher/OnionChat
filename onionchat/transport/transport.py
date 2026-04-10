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
    """Tor hidden service transport."""
    
    def __init__(self, config: TransportConfig, is_server: bool = False):
        super().__init__(config)
        self.is_server = is_server
        self._onion_address: Optional[str] = None
        self._tor_process: Optional[asyncio.subprocess.Process] = None
        self._server: Optional[asyncio.Server] = None
    
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
            # Start local server
            self._server = await asyncio.start_server(
                self._handle_client,
                self.config.host,
                self.config.port
            )
            
            # TODO: Integrate with Tor controller (stem/torpy)
            # For now, simulate onion address
            self._onion_address = f"test-onion-{self.config.port}.onion"
            self._connected = True
            
            logger.info(f"Tor server started on {self._onion_address}")
        except Exception as e:
            raise TransportError(f"Failed to start Tor server: {e}", "TOR_SERVER_FAILED")
    
    async def _connect_via_tor(self) -> None:
        """Connect to onion service via Tor."""
        try:
            # TODO: Use Tor SOCKS proxy
            # For now, fall back to direct connection for testing
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.host, self.config.port),
                timeout=self.config.timeout
            )
            self._connected = True
            logger.info("Connected via Tor (simulated)")
        except asyncio.TimeoutError:
            raise TransportError("Tor connection timeout", "TOR_TIMEOUT")
        except Exception as e:
            raise TransportError(f"Tor connection failed: {e}", "TOR_CONNECTION_FAILED")
    
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
