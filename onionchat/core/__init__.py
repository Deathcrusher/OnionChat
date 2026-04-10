"""Core cryptographic operations and protocol for OnionChat."""

from .crypto import (
    KeyPair,
    SessionKeys,
    CryptoError,
    secure_zero,
    generate_rsa_keys,
    generate_ecdh_keys,
    derive_session_keys,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_signature,
    constant_time_compare,
)

from .protocol import (
    MessageType,
    SessionState,
    ProtocolMessage,
    SessionConfig,
    SessionCredentials,
    SessionInfo,
    SessionError,
)

from .session import (
    ChatSession,
    ChatMessage,
    FileTransfer,
)

__all__ = [
    # Crypto
    "KeyPair",
    "SessionKeys",
    "CryptoError",
    "secure_zero",
    "generate_rsa_keys",
    "generate_ecdh_keys",
    "derive_session_keys",
    "encrypt_message",
    "decrypt_message",
    "sign_message",
    "verify_signature",
    "constant_time_compare",
    # Protocol
    "MessageType",
    "SessionState",
    "ProtocolMessage",
    "SessionConfig",
    "SessionCredentials",
    "SessionInfo",
    "SessionError",
    # Session
    "ChatSession",
    "ChatMessage",
    "FileTransfer",
]
