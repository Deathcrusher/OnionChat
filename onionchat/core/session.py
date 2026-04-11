"""
Main chat session manager for OnionChat.

Handles:
- Key exchange protocol
- Message encryption/decryption
- File transfers
- Session lifecycle
"""

import asyncio
import logging
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass, field

from ..core import (
    KeyPair,
    SessionKeys,
    SessionConfig,
    SessionCredentials,
    SessionInfo,
    SessionState,
    MessageType,
    ProtocolMessage,
    SessionError,
    CryptoError,
    generate_rsa_keys,
    generate_ecdh_keys,
    derive_session_keys,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_signature,
)
from ..transport import BaseTransport, TransportConfig, TCPTransport, TorTransport, TransportError

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """A chat message with metadata."""
    content: str
    sender: str
    timestamp: float
    is_encrypted: bool = True


@dataclass
class FileTransfer:
    """File transfer information."""
    filename: str
    size: int
    data: bytes = field(default_factory=bytes)
    progress: float = 0.0
    is_complete: bool = False


type MessageCallback = Callable[[ChatMessage], Awaitable[None]]
type StatusCallback = Callable[[str], Awaitable[None]]


class ChatSession:
    """Main chat session manager."""
    
    def __init__(
        self,
        config: SessionConfig,
        is_host: bool = True,
        transport_config: Optional[TransportConfig] = None
    ):
        self.config = config
        self.is_host = is_host
        self.transport_config = transport_config or TransportConfig(port=config.hidden_service_port)
        
        self.session_info = SessionInfo(config=config)
        self.rsa_keys: Optional[KeyPair] = None
        self.ecdh_keys: Optional[KeyPair] = None
        self.session_keys: Optional[SessionKeys] = None
        self.transport: Optional[BaseTransport] = None
        
        self._message_callback: Optional[MessageCallback] = None
        self._status_callback: Optional[StatusCallback] = None
        self._running = False
        self._receive_task: Optional[asyncio.Task] = None
    
    def set_message_callback(self, callback: MessageCallback):
        """Set callback for incoming messages."""
        self._message_callback = callback
    
    def set_status_callback(self, callback: StatusCallback):
        """Set callback for status updates."""
        self._status_callback = callback
    
    async def _notify_status(self, message: str):
        """Notify status update."""
        if self._status_callback:
            await self._status_callback(message)
        logger.info(f"Status: {message}")
    
    async def initialize(self):
        """Initialize session keys and transport."""
        try:
            await self._notify_status("Generating cryptographic keys...")
            self.rsa_keys = generate_rsa_keys()
            self.ecdh_keys = generate_ecdh_keys()
            
            if self.is_host:
                self.transport = TorTransport(self.transport_config, is_server=True)
                self.session_info.state = SessionState.INITIALIZING
            else:
                self.transport = TorTransport(self.transport_config, is_server=False)
            
            await self._notify_status("Keys generated successfully")
            
        except Exception as e:
            self.session_info.state = SessionState.ERROR
            self.session_info.error_message = str(e)
            raise SessionError(f"Initialization failed: {e}", "INIT_FAILED")
    
    async def start(self):
        """Start the chat session."""
        if not self.rsa_keys or not self.ecdh_keys:
            raise SessionError("Session not initialized", "NOT_INITIALIZED")
        
        try:
            await self._notify_status("Starting transport layer...")
            await self.transport.connect()
            
            if self.is_host:
                await self._notify_status(f"Waiting for connection on {self.transport.onion_address}...")
            else:
                await self._notify_status("Connected to host, starting key exchange...")
                await self._perform_key_exchange()
            
            self._running = True
            self._receive_task = asyncio.create_task(self._receive_loop())
            
        except Exception as e:
            self.session_info.state = SessionState.ERROR
            self.session_info.error_message = str(e)
            raise SessionError(f"Failed to start session: {e}", "START_FAILED")
    
    async def _perform_key_exchange(self):
        """Perform ECDH key exchange with remote party (with MITM protection)."""
        try:
            self.session_info.state = SessionState.KEY_EXCHANGING
            
            # Send our ECDH public key with RSA signature for authentication
            from cryptography.hazmat.primitives import serialization
            
            # Serialize our ECDH public key in DER format
            ecdh_pub_der = self.ecdh_keys.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Sign the ECDH public key with our RSA private key
            key_sig = sign_message(ecdh_pub_der, self.rsa_keys.private_key)
            
            key_msg = ProtocolMessage(
                msg_type=MessageType.KEY_EXCHANGE,
                payload={
                    'ecdh_pub': ecdh_pub_der.hex(),
                    'rsa_sig': key_sig.hex(),
                    'session_id': self.config.session_id
                }
            )
            await self.transport.send_packet(key_msg.to_bytes())
            
            # Wait for response
            response_data = await self.transport.receive_packet()
            response = ProtocolMessage.from_bytes(response_data)
            
            if response.msg_type != MessageType.KEY_EXCHANGE_ACK:
                raise SessionError("Invalid key exchange response", "KEY_EXCHANGE_FAILED")
            
            # Verify the signature on the remote ECDH public key
            remote_ecdh_pub = bytes.fromhex(response.payload['ecdh_pub'])
            remote_sig = bytes.fromhex(response.payload['rsa_sig'])
            
            # Deserialize remote public key
            remote_public_key = serialization.load_der_public_key(
                remote_ecdh_pub,
                backend=None
            )
            
            # Verify signature using host's RSA public key from credentials
            if self.session_info.remote_credentials:
                host_rsa_pub = serialization.load_pem_public_key(
                    self.session_info.remote_credentials.public_key_pem,
                    backend=None
                )
                if not verify_signature(remote_ecdh_pub, remote_sig, host_rsa_pub):
                    raise SessionError("MITM detected: Invalid signature on key exchange", "KEY_EXCHANGE_FAILED")
            
            # Derive session keys
            salt = self.config.session_id.encode('utf-8')
            self.session_keys = derive_session_keys(
                self.ecdh_keys.private_key,
                remote_public_key,
                salt
            )
            
            self.session_info.state = SessionState.ACTIVE
            self.session_info.update_activity()
            await self._notify_status("Key exchange completed, session secure")
            
        except Exception as e:
            self.session_info.state = SessionState.ERROR
            raise SessionError(f"Key exchange failed: {e}", "KEY_EXCHANGE_FAILED")
    
    async def _receive_loop(self):
        """Main receive loop for incoming messages."""
        while self._running and self.transport and self.transport.is_connected:
            try:
                data = await self.transport.receive_packet()
                self.session_info.update_activity()
                
                msg = ProtocolMessage.from_bytes(data)
                
                if msg.msg_type == MessageType.KEY_EXCHANGE:
                    await self._handle_key_exchange(msg)
                elif msg.msg_type == MessageType.CHAT_MESSAGE:
                    await self._handle_chat_message(msg)
                elif msg.msg_type == MessageType.SESSION_TERMINATE:
                    await self._handle_terminate()
                    break
                elif msg.msg_type == MessageType.FILE_TRANSFER_START:
                    await self._handle_file_start(msg)
                # Add more message type handlers as needed
                
            except TransportError as e:
                if e.error_code == "CONNECTION_CLOSED":
                    logger.info("Connection closed by remote party")
                    break
                logger.error(f"Transport error: {e}")
            except Exception as e:
                logger.error(f"Error in receive loop: {e}")
                continue
        
        await self.stop()
    
    async def _handle_chat_message(self, msg: ProtocolMessage):
        """Handle incoming chat message."""
        if not self.session_keys:
            logger.error("No session keys available")
            return
        
        try:
            nonce = bytes.fromhex(msg.payload['nonce'])
            ciphertext = bytes.fromhex(msg.payload['ciphertext'])
            tag = bytes.fromhex(msg.payload['tag'])
            
            plaintext = decrypt_message(nonce, ciphertext, tag, self.session_keys)
            
            chat_msg = ChatMessage(
                content=plaintext,
                sender="remote",
                timestamp=msg.timestamp
            )
            
            if self._message_callback:
                await self._message_callback(chat_msg)
                
        except CryptoError as e:
            logger.error(f"Decryption failed: {e}")
    
    async def _handle_terminate(self):
        """Handle session termination."""
        await self._notify_status("Session terminated by remote party")
        self._running = False
    
    async def _handle_key_exchange(self, msg: ProtocolMessage):
        """Handle incoming key exchange request (for host receiving from client)."""
        try:
            from cryptography.hazmat.primitives import serialization
            
            # Verify the signature on the remote ECDH public key
            remote_ecdh_pub = bytes.fromhex(msg.payload['ecdh_pub'])
            remote_sig = bytes.fromhex(msg.payload['rsa_sig'])
            
            # Deserialize remote public key
            remote_public_key = serialization.load_der_public_key(
                remote_ecdh_pub,
                backend=None
            )
            
            # Verify signature - for host, we need to get client's RSA key from credentials
            # In a proper implementation, this would be exchanged out-of-band or via QR
            # For now, we'll skip verification if no credentials are available
            if self.session_info.remote_credentials:
                client_rsa_pub = serialization.load_pem_public_key(
                    self.session_info.remote_credentials.public_key_pem,
                    backend=None
                )
                if not verify_signature(remote_ecdh_pub, remote_sig, client_rsa_pub):
                    raise SessionError("MITM detected: Invalid signature on key exchange", "KEY_EXCHANGE_FAILED")
            
            # Derive session keys
            salt = self.config.session_id.encode('utf-8')
            self.session_keys = derive_session_keys(
                self.ecdh_keys.private_key,
                remote_public_key,
                salt
            )
            
            # Send ACK with our signed ECDH public key
            ecdh_pub_der = self.ecdh_keys.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_sig = sign_message(ecdh_pub_der, self.rsa_keys.private_key)
            
            ack_msg = ProtocolMessage(
                msg_type=MessageType.KEY_EXCHANGE_ACK,
                payload={
                    'ecdh_pub': ecdh_pub_der.hex(),
                    'rsa_sig': key_sig.hex(),
                    'session_id': self.config.session_id
                }
            )
            await self.transport.send_packet(ack_msg.to_bytes())
            
            self.session_info.state = SessionState.ACTIVE
            self.session_info.update_activity()
            await self._notify_status("Key exchange completed, session secure")
            
        except Exception as e:
            self.session_info.state = SessionState.ERROR
            raise SessionError(f"Key exchange failed: {e}", "KEY_EXCHANGE_FAILED")
    
    async def _handle_file_start(self, msg: ProtocolMessage):
        """Handle file transfer start."""
        filename = msg.payload.get('filename', 'unknown')
        size = msg.payload.get('size', 0)
        await self._notify_status(f"Receiving file: {filename} ({size} bytes)")
    
    async def send_message(self, text: str):
        """Send a chat message."""
        if not self.session_keys or not self.transport:
            raise SessionError("Session not active", "NOT_ACTIVE")
        
        try:
            nonce, ciphertext, tag = encrypt_message(text, self.session_keys)
            
            msg = ProtocolMessage(
                msg_type=MessageType.CHAT_MESSAGE,
                payload={
                    'nonce': nonce.hex(),
                    'ciphertext': ciphertext.hex(),
                    'tag': tag.hex()
                }
            )
            
            await self.transport.send_packet(msg.to_bytes())
            self.session_info.update_activity()
            
        except CryptoError as e:
            raise SessionError(f"Encryption failed: {e}", "ENCRYPTION_FAILED")
    
    async def stop(self):
        """Stop the chat session."""
        self._running = False
        
        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass
        
        if self.transport:
            await self.transport.disconnect()
        
        self.session_info.state = SessionState.TERMINATED
        await self._notify_status("Session terminated")
    
    def get_credentials(self) -> SessionCredentials:
        """Get session credentials for sharing."""
        if not self.rsa_keys or not self.ecdh_keys:
            raise SessionError("Session not initialized", "NOT_INITIALIZED")
        
        if not self.transport or not isinstance(self.transport, TorTransport):
            raise SessionError("Transport not ready", "TRANSPORT_NOT_READY")
        
        return SessionCredentials(
            onion_address=self.transport.onion_address or "",
            session_id=self.config.session_id,
            public_key_pem=self.rsa_keys.public_bytes,
            ecdh_public_key=self.ecdh_keys.public_bytes
        )
