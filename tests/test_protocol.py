"""Unit tests for protocol module."""

import pytest
import json
from onionchat.core.protocol import (
    MessageType,
    SessionState,
    ProtocolMessage,
    SessionConfig,
    SessionCredentials,
    SessionInfo,
)


class TestProtocolMessage:
    """Test protocol message serialization."""
    
    def test_message_serialization(self):
        """Test message to_bytes and from_bytes."""
        msg = ProtocolMessage(
            msg_type=MessageType.CHAT_MESSAGE,
            payload={'text': 'Hello'}
        )
        
        data = msg.to_bytes()
        restored = ProtocolMessage.from_bytes(data)
        
        assert restored.msg_type == msg.msg_type
        assert restored.payload == msg.payload
    
    def test_message_types(self):
        """Test all message types can be serialized."""
        for msg_type in MessageType:
            msg = ProtocolMessage(msg_type=msg_type, payload={})
            data = msg.to_bytes()
            restored = ProtocolMessage.from_bytes(data)
            assert restored.msg_type == msg_type


class TestSessionConfig:
    """Test session configuration."""
    
    def test_generate_config(self):
        """Test config generation."""
        config = SessionConfig.generate()
        assert len(config.session_id) == 64  # 32 bytes hex
        assert config.tor_port == 9050
        assert config.hidden_service_port == 8080
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = SessionConfig(
            session_id="test123",
            tor_port=9999,
            max_file_size_mb=50
        )
        assert config.session_id == "test123"
        assert config.tor_port == 9999
        assert config.max_file_size_mb == 50


class TestSessionCredentials:
    """Test session credentials."""
    
    def test_credentials_qr_roundtrip(self):
        """Test credentials serialization to QR and back."""
        creds = SessionCredentials(
            onion_address="test.onion",
            session_id="abc123",
            public_key_pem=b"rsa_key_data",
            ecdh_public_key=b"ecdh_key_data"
        )
        
        qr_data = creds.to_qr_data()
        restored = SessionCredentials.from_qr_data(qr_data)
        
        assert restored.onion_address == creds.onion_address
        assert restored.session_id == creds.session_id
        assert restored.public_key_pem == creds.public_key_pem
        assert restored.ecdh_public_key == creds.ecdh_public_key
    
    def test_qr_data_is_valid_json(self):
        """Test QR data is valid JSON."""
        creds = SessionCredentials(
            onion_address="test.onion",
            session_id="abc123",
            public_key_pem=b"rsa",
            ecdh_public_key=b"ecdh"
        )
        
        qr_data = creds.to_qr_data()
        data = json.loads(qr_data)
        
        assert 'onion' in data
        assert 'session_id' in data
        assert 'rsa_pub' in data
        assert 'ecdh_pub' in data


class TestSessionInfo:
    """Test session info."""
    
    def test_session_info_creation(self):
        """Test session info creation."""
        config = SessionConfig.generate()
        info = SessionInfo(config=config)
        
        assert info.state == SessionState.INITIALIZING
        assert info.config == config
        assert info.error_message is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
