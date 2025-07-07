import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from onionchat.chat_utils import (
    encrypt_bytes,
    decrypt_bytes,
    encrypt_qr_data,
    decrypt_qr_data,
)
import pytest

def test_encrypt_decrypt_bytes():
    key = b'1' * 32
    nonce, ct, tag = encrypt_bytes(b'secret', key)
    assert decrypt_bytes(nonce, ct, tag, key) == b'secret'


def test_decrypt_qr_data_bad_passphrase():
    salt, nonce, ct, tag = encrypt_qr_data('o', 's', b'pub', 'good')
    with pytest.raises(Exception):
        decrypt_qr_data(salt, nonce, ct, tag, 'bad')
