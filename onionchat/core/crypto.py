"""
Core cryptographic operations for OnionChat.

Implements:
- RSA-4096 for authentication
- ECDH (X25519) for key exchange with forward secrecy
- HKDF for secure key derivation
- AES-256-GCM for message encryption
- Secure memory wiping
"""

import os
import ctypes
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class KeyPair:
    """RSA, ECDH, or X25519 key pair."""
    private_key: object
    public_key: object
    public_bytes: bytes = field(default_factory=bytes, repr=False)
    
    def __post_init__(self):
        if self.public_bytes == b"":
            # Handle X25519 keys
            if isinstance(self.public_key, x25519.X25519PublicKey):
                self.public_bytes = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            # Handle EC keys
            elif isinstance(self.public_key, ec.EllipticCurvePublicKey):
                self.public_bytes = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            # Handle RSA keys
            else:
                self.public_bytes = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.PKCS1,
                )


@dataclass
class SessionKeys:
    """Derived session keys with metadata."""
    shared_secret: bytes = field(repr=False)
    encryption_key: bytes = field(repr=False)
    authentication_key: bytes = field(repr=False)
    nonce_counter: int = 0
    
    def get_nonce(self) -> bytes:
        """Get next nonce and increment counter."""
        nonce = self.nonce_counter.to_bytes(12, 'big')
        self.nonce_counter += 1
        return nonce


class CryptoError(Exception):
    """Custom exception for crypto operations."""
    def __init__(self, message: str, error_code: str = "CRYPTO_ERROR"):
        super().__init__(message)
        self.error_code = error_code


def secure_zero(data: bytearray) -> None:
    """Securely zero out sensitive data in memory."""
    if not data:
        return
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.mlock(ctypes.byref((ctypes.c_char * len(data)).from_buffer(data)), len(data))
    except Exception:
        pass
    
    for i in range(len(data)):
        data[i] = 0
    
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.munlock(ctypes.byref((ctypes.c_char * len(data)).from_buffer(data)), len(data))
    except Exception:
        pass


def generate_rsa_keys(key_size: int = 4096) -> KeyPair:
    """Generate RSA key pair for authentication."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return KeyPair(private_key=private_key, public_key=public_key)


def generate_ecdh_keys() -> KeyPair:
    """Generate ECDH (X25519) key pair for key exchange."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return KeyPair(private_key=private_key, public_key=public_key)


def derive_session_keys(
    local_private: x25519.X25519PrivateKey,
    remote_public: x25519.X25519PublicKey,
    salt: bytes
) -> SessionKeys:
    """Derive session keys using ECDH and HKDF (proper key derivation)."""
    # Perform ECDH to get shared secret
    shared_secret = local_private.exchange(remote_public)
    
    # Use HKDF for proper key derivation (not PBKDF2 which is for passwords)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"onionchat-session-keys",
        backend=default_backend()
    )
    derived = hkdf.derive(shared_secret)
    
    encryption_key = derived[:32]
    authentication_key = derived[32:]
    
    return SessionKeys(
        shared_secret=shared_secret,
        encryption_key=encryption_key,
        authentication_key=authentication_key
    )


def encrypt_message(
    plaintext: str,
    session_keys: SessionKeys,
    associated_data: Optional[bytes] = None
) -> tuple[bytes, bytes, bytes]:
    """Encrypt a message using AES-256-GCM."""
    nonce = session_keys.get_nonce()
    aesgcm = AESGCM(session_keys.encryption_key)
    
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), associated_data)
    
    tag = ciphertext[-16:]
    ciphertext = ciphertext[:-16]
    
    return nonce, ciphertext, tag


def decrypt_message(
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    session_keys: SessionKeys,
    associated_data: Optional[bytes] = None
) -> str:
    """Decrypt a message using AES-256-GCM."""
    aesgcm = AESGCM(session_keys.encryption_key)
    
    full_ciphertext = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, full_ciphertext, associated_data)
    
    return plaintext.decode('utf-8')


def sign_message(
    message: bytes,
    private_key: rsa.RSAPrivateKey
) -> bytes:
    """Sign a message with RSA-PSS."""
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(
    message: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey
) -> bool:
    """Verify an RSA-PSS signature."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
