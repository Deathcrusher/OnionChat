"""
Protocol definitions and session management for OnionChat.
"""

import asyncio
import json
import os
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import Optional, Dict, Any
from pathlib import Path


class MessageType(Enum):
    """Types of messages in the protocol."""
    KEY_EXCHANGE = auto()
    KEY_EXCHANGE_ACK = auto()
    CHAT_MESSAGE = auto()
    FILE_TRANSFER_START = auto()
    FILE_TRANSFER_CHUNK = auto()
    FILE_TRANSFER_END = auto()
    SESSION_TERMINATE = auto()
    ERROR = auto()


class SessionState(Enum):
    """Session lifecycle states."""
    INITIALIZING = auto()
    KEY_EXCHANGING = auto()
    ACTIVE = auto()
    TERMINATING = auto()
    TERMINATED = auto()
    ERROR = auto()


@dataclass
class ProtocolMessage:
    """Base protocol message structure."""
    msg_type: MessageType
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0)
    
    def to_bytes(self) -> bytes:
        """Serialize message to bytes."""
        data = {
            'type': self.msg_type.name,
            'payload': self.payload,
            'timestamp': self.timestamp
        }
        return json.dumps(data).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ProtocolMessage':
        """Deserialize message from bytes."""
        obj = json.loads(data.decode('utf-8'))
        msg_type = MessageType[obj['type']]
        return cls(
            msg_type=msg_type,
            payload=obj['payload'],
            timestamp=obj['timestamp']
        )


@dataclass
class SessionConfig:
    """Configuration for a chat session."""
    session_id: str
    tor_port: int = 9050
    control_port: int = 9051
    hidden_service_port: int = 8080
    max_file_size_mb: int = 100
    timeout_seconds: int = 300
    padding_enabled: bool = True
    tor_impl: str = "stem"  # or "torpy"
    
    @classmethod
    def generate(cls) -> 'SessionConfig':
        """Generate a new session config with random session ID."""
        return cls(session_id=os.urandom(32).hex())


@dataclass
class SessionCredentials:
    """Credentials needed to join a session."""
    onion_address: str
    session_id: str
    public_key_pem: bytes
    ecdh_public_key: bytes
    
    def to_qr_data(self) -> str:
        """Serialize credentials to QR code format."""
        import base64
        data = {
            'onion': self.onion_address,
            'session_id': self.session_id,
            'rsa_pub': base64.b64encode(self.public_key_pem).decode('ascii'),
            'ecdh_pub': base64.b64encode(self.ecdh_public_key).decode('ascii')
        }
        return json.dumps(data)
    
    @classmethod
    def from_qr_data(cls, qr_data: str) -> 'SessionCredentials':
        """Deserialize credentials from QR code format."""
        import base64
        data = json.loads(qr_data)
        return cls(
            onion_address=data['onion'],
            session_id=data['session_id'],
            public_key_pem=base64.b64decode(data['rsa_pub']),
            ecdh_public_key=base64.b64decode(data['ecdh_pub'])
        )


@dataclass
class SessionInfo:
    """Runtime session information."""
    config: SessionConfig
    state: SessionState = SessionState.INITIALIZING
    local_onion: Optional[str] = None
    remote_credentials: Optional[SessionCredentials] = None
    error_message: Optional[str] = None
    created_at: float = field(default_factory=lambda: asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0)
    last_activity: float = field(default_factory=lambda: asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0)
    
    def is_expired(self) -> bool:
        """Check if session has timed out."""
        if asyncio.get_event_loop().is_running():
            current_time = asyncio.get_event_loop().time()
        else:
            import time
            current_time = time.time()
        return (current_time - self.last_activity) > self.config.timeout_seconds
    
    def update_activity(self):
        """Update last activity timestamp."""
        if asyncio.get_event_loop().is_running():
            self.last_activity = asyncio.get_event_loop().time()
        else:
            import time
            self.last_activity = time.time()


class SessionError(Exception):
    """Custom exception for session errors."""
    def __init__(self, message: str, error_code: str = "SESSION_ERROR"):
        super().__init__(message)
        self.error_code = error_code
