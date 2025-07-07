import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from onionchat.chat_utils import (
    encrypt_message,
    decrypt_message,
    encrypt_qr_data,
    decrypt_qr_data,
)


def test_encrypt_decrypt_message():
    key = b"0" * 32
    nonce, ct, tag = encrypt_message("hello", key, 32)
    assert decrypt_message(nonce, ct, tag, key) == "hello"


def test_encrypt_decrypt_qr_data():
    salt, nonce, ct, tag = encrypt_qr_data("onion", "session", b"pub", "pass")
    onion, sess, pub = decrypt_qr_data(salt, nonce, ct, tag, "pass")
    assert onion == "onion"
    assert sess == "session"
    assert pub == b"pub"
