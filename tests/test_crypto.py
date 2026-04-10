"""Unit tests for crypto module."""

import pytest
from onionchat.core.crypto import (
    generate_rsa_keys,
    generate_ecdh_keys,
    derive_session_keys,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_signature,
    constant_time_compare,
    SessionKeys,
)


class TestRSAKeys:
    """Test RSA key generation."""
    
    def test_generate_rsa_keys(self):
        """Test RSA key pair generation."""
        keypair = generate_rsa_keys(2048)  # Use smaller size for speed
        assert keypair.private_key is not None
        assert keypair.public_key is not None
        assert len(keypair.public_bytes) > 0
    
    def test_rsa_keys_deterministic(self):
        """Test that each call generates different keys."""
        kp1 = generate_rsa_keys(2048)
        kp2 = generate_rsa_keys(2048)
        assert kp1.public_bytes != kp2.public_bytes


class TestECDHKeys:
    """Test ECDH key generation."""
    
    def test_generate_ecdh_keys(self):
        """Test ECDH key pair generation."""
        keypair = generate_ecdh_keys()
        assert keypair.private_key is not None
        assert keypair.public_key is not None
        assert len(keypair.public_bytes) > 0


class TestSessionKeys:
    """Test session key derivation."""
    
    def test_derive_session_keys(self):
        """Test session key derivation from ECDH."""
        alice = generate_ecdh_keys()
        bob = generate_ecdh_keys()
        
        salt = b"test_salt_123"
        
        alice_keys = derive_session_keys(alice.private_key, bob.public_key, salt)
        bob_keys = derive_session_keys(bob.private_key, alice.public_key, salt)
        
        # Both parties should derive the same keys
        assert alice_keys.encryption_key == bob_keys.encryption_key
        assert alice_keys.authentication_key == bob_keys.authentication_key
    
    def test_session_keys_different_salts(self):
        """Test that different salts produce different keys."""
        alice = generate_ecdh_keys()
        bob = generate_ecdh_keys()
        
        keys1 = derive_session_keys(alice.private_key, bob.public_key, b"salt1")
        keys2 = derive_session_keys(alice.private_key, bob.public_key, b"salt2")
        
        assert keys1.encryption_key != keys2.encryption_key


class TestEncryption:
    """Test message encryption/decryption."""
    
    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        alice = generate_ecdh_keys()
        bob = generate_ecdh_keys()
        
        salt = b"test_salt"
        session_keys = derive_session_keys(alice.private_key, bob.public_key, salt)
        
        message = "Hello, World!"
        nonce, ciphertext, tag = encrypt_message(message, session_keys)
        
        decrypted = decrypt_message(nonce, ciphertext, tag, session_keys)
        assert decrypted == message
    
    def test_encryption_changes_ciphertext(self):
        """Test that each encryption produces different ciphertext."""
        alice = generate_ecdh_keys()
        bob = generate_ecdh_keys()
        
        salt = b"test_salt"
        session_keys = derive_session_keys(alice.private_key, bob.public_key, salt)
        
        message = "Same message"
        
        n1, c1, t1 = encrypt_message(message, session_keys)
        n2, c2, t2 = encrypt_message(message, session_keys)
        
        # Nonces should be different (counter-based)
        assert n1 != n2
        # Ciphertexts should be different due to different nonces
        assert c1 != c2


class TestSigning:
    """Test message signing."""
    
    def test_sign_verify(self):
        """Test signing and verification."""
        keys = generate_rsa_keys(2048)
        message = b"Test message"
        
        signature = sign_message(message, keys.private_key)
        assert verify_signature(message, signature, keys.public_key)
    
    def test_sign_wrong_message(self):
        """Test verification fails with wrong message."""
        keys = generate_rsa_keys(2048)
        message = b"Test message"
        wrong_message = b"Wrong message"
        
        signature = sign_message(message, keys.private_key)
        assert not verify_signature(wrong_message, signature, keys.public_key)


class TestConstantTimeCompare:
    """Test constant-time comparison."""
    
    def test_equal_strings(self):
        """Test equal strings return True."""
        assert constant_time_compare(b"hello", b"hello")
        assert constant_time_compare(b"", b"")
    
    def test_different_strings(self):
        """Test different strings return False."""
        assert not constant_time_compare(b"hello", b"world")
        assert not constant_time_compare(b"hello", b"hell")
        assert not constant_time_compare(b"hello", b"hello!")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
