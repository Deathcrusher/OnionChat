import sys
import os
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from chat_utils import encrypt_message, decrypt_message, secure_wipe


def test_encrypt_message_too_long():
    key = b"0" * 32
    with pytest.raises(ValueError):
        encrypt_message("a" * 2000, key, 32)


def test_secure_wipe():
    data = bytearray(b"secret")
    secure_wipe(data)
    assert all(b == 0 for b in data)


def test_cli_parsing():
    import client_a_main
    args = client_a_main.parse_args([])
    assert args.port == 12345


def test_client_b_default_args():
    import client_b_main
    args = client_b_main.parse_args([])
    assert args.padding == 1024
    assert args.max_file_size == 100
    assert args.tor_impl == "torpy"
    assert args.onion is None
    assert args.session is None
    assert args.key is None

