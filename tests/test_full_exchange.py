import os
import sys
import socket
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, x25519

from onionchat.chat_utils import (
    generate_keys,
    derive_session_key,
    encrypt_message,
    decrypt_message,
    encrypt_bytes,
    decrypt_bytes,
)

# The library version used in tests may not expose `serialization.Raw` constant.
# Client code expects it, so provide it if missing.
if not hasattr(serialization, "Raw"):
    serialization.Raw = serialization.Encoding.Raw


def test_full_exchange(tmp_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_sock:
        temp_sock.bind(("localhost", 0))
        port = temp_sock.getsockname()[1]
    session_id = "testsession"

    rsa_private, rsa_public, rsa_public_bytes, ecdh_private, ecdh_public_bytes = generate_keys()
    key_file = tmp_path / "pub.pem"
    key_file.write_bytes(rsa_public_bytes)

    results = {}
    file_payload = b"secret-data"

    def send_packet(sock, payload):
        sock.sendall(len(payload).to_bytes(4, "big") + payload)

    def recv_exact(sock, n):
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise RuntimeError("connection closed")
            data += chunk
        return data

    def recv_packet(sock):
        length = int.from_bytes(recv_exact(sock, 4), "big")
        return recv_exact(sock, length)

    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("localhost", port))
        srv.listen(1)
        conn, _ = srv.accept()

        recv_session = recv_exact(conn, len(session_id)).decode()
        assert recv_session == session_id
        enc_key = recv_exact(conn, 512)
        peer_ecdh_bytes = rsa_private.decrypt(
            enc_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        session_key = derive_session_key(ecdh_private, peer_ecdh_bytes)
        conn.sendall(ecdh_public_bytes)

        n, ct, tag = encrypt_message("hello_b", session_key, 1024)
        send_packet(conn, n + tag + ct)

        data = recv_packet(conn)
        n, tag, ct = data[:12], data[12:28], data[28:]
        results["msg_from_b"] = decrypt_message(n, ct, tag, session_key)

        data = recv_packet(conn)
        n, tag, ct = data[:12], data[12:28], data[28:]
        header = decrypt_message(n, ct, tag, session_key)
        assert header.startswith("FILE_TRANSFER_START:")
        _, fname, fsize = header.split(":", 2)
        fsize = int(fsize)
        recv_bytes = b""
        chunk = recv_packet(conn)
        n, tag, ct = chunk[:12], chunk[12:28], chunk[28:]
        recv_bytes += decrypt_bytes(n, ct, tag, session_key)
        end = recv_packet(conn)
        n, tag, ct = end[:12], end[12:28], end[28:]
        assert decrypt_message(n, ct, tag, session_key) == "FILE_TRANSFER_END"
        results["file_from_b"] = recv_bytes[:fsize]

        sig = rsa_private.sign(
            b"TERMINATE",
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        send_packet(conn, sig)
        conn.close()
        srv.close()

    def client():
        time.sleep(0.1)
        sock = socket.create_connection(("localhost", port))
        rsa_public_key = serialization.load_pem_public_key(key_file.read_bytes())
        ecdh_priv = x25519.X25519PrivateKey.generate()
        ecdh_pub = ecdh_priv.public_key().public_bytes(
            encoding=serialization.Raw,
            format=serialization.PublicFormat.Raw,
        )
        enc_key = rsa_public_key.encrypt(
            ecdh_pub,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        sock.sendall(session_id.encode())
        time.sleep(0.05)
        sock.sendall(enc_key)
        peer = recv_exact(sock, 32)
        session_key = derive_session_key(ecdh_priv, peer)

        data = recv_packet(sock)
        n, tag, ct = data[:12], data[12:28], data[28:]
        results["msg_from_a"] = decrypt_message(n, ct, tag, session_key)

        n, ct, tag = encrypt_message("hello_a", session_key, 1024)
        send_packet(sock, n + tag + ct)

        header = f"FILE_TRANSFER_START:test.txt:{len(file_payload)}"
        n, ct, tag = encrypt_message(header, session_key, 1024)
        send_packet(sock, n + tag + ct)
        n_data, c_data, t_data = encrypt_bytes(file_payload, session_key)
        send_packet(sock, n_data + t_data + c_data)
        n, ct, tag = encrypt_message("FILE_TRANSFER_END", session_key, 1024)
        send_packet(sock, n + tag + ct)

        sig = recv_packet(sock)
        rsa_public_key.verify(
            sig,
            b"TERMINATE",
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        results["terminated"] = True
        sock.close()

    t1 = threading.Thread(target=server)
    t2 = threading.Thread(target=client)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results["msg_from_a"] == "hello_b"
    assert results["msg_from_b"] == "hello_a"
    assert results["file_from_b"] == file_payload
    assert results["terminated"]
