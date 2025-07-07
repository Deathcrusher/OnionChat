"""Shared utilities for OnionChat including crypto operations, QR code handling, and Tor hidden service setup."""
import os
import secrets
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import ImageTk

try:
    from torpy import TorClient
except Exception:  # pragma: no cover - network dependency
    TorClient = None

try:
    import qrcode
    from pyzbar.pyzbar import decode
    import cv2
except Exception:  # pragma: no cover - optional dependencies
    qrcode = None
    decode = None
    cv2 = None

try:
    import pyperclip
except Exception:
    pyperclip = None

try:
    from stem.control import Controller
except Exception:  # pragma: no cover - optional dependency
    Controller = None


# Wipe sensitive data from memory
# Best-effort; due to Python memory management this cannot guarantee removal.
def secure_wipe(data):
    """Best-effort overwrite of sensitive data."""
    if data is None:
        return
    try:
        if isinstance(data, bytes):
            ba = bytearray(data)
        else:
            ba = data
        rnd = secrets.token_bytes(len(ba))
        for i in range(len(ba)):
            ba[i] = rnd[i]
        for i in range(len(ba)):
            ba[i] = 0
    except Exception:
        pass


def generate_keys():
    """Generate RSA and ECDH key pairs."""
    rsa_private = rsa.generate_private_key(
        public_exponent=65537, key_size=4096
    )
    rsa_public = rsa_private.public_key()
    rsa_bytes = rsa_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ecdh_private = x25519.X25519PrivateKey.generate()
    ecdh_public = ecdh_private.public_key()
    ecdh_bytes = ecdh_public.public_bytes(
        encoding=serialization.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return rsa_private, rsa_public, rsa_bytes, ecdh_private, ecdh_bytes


def derive_session_key(ecdh_private, peer_bytes):
    """Derive a session key using ECDH."""
    peer_public = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
    shared = ecdh_private.exchange(peer_public)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chat_session",
    ).derive(shared)


def encrypt_message(message: str, key: bytes, padding_len: int):
    """Encrypt a message with AES-256-GCM using fixed padding."""
    data = message.encode()
    length = len(data)
    if length + 4 > padding_len:
        raise ValueError("Message too long for padding")
    pad = secrets.token_bytes(padding_len - length - 4)
    padded = length.to_bytes(4, "big") + data + pad
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return nonce, ct, enc.tag


def decrypt_message(nonce: bytes, ct: bytes, tag: bytes, key: bytes):
    """Decrypt a padded message encrypted by :func:`encrypt_message`."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    length = int.from_bytes(padded[:4], "big")
    return padded[4:4 + length].decode()


def encrypt_bytes(data: bytes, key: bytes):
    """Encrypt arbitrary bytes with AES-256-GCM."""
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()
    return nonce, ct, enc.tag


def decrypt_bytes(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> bytes:
    """Decrypt bytes encrypted with :func:`encrypt_bytes`."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()


def encrypt_qr_data(onion: str, session_id: str, rsa_bytes: bytes, passphrase: str):
    """Encrypt connection info for QR code transfer."""
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(passphrase.encode())
    payload = f"{onion}|{session_id}|{rsa_bytes.decode()}".encode()
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    enc = cipher.encryptor()
    ct = enc.update(payload) + enc.finalize()
    return salt, nonce, ct, enc.tag


def decrypt_qr_data(salt: bytes, nonce: bytes, ct: bytes, tag: bytes, passphrase: str):
    """Decrypt QR code data using the provided passphrase."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(passphrase.encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    dec = cipher.decryptor()
    data = dec.update(ct) + dec.finalize()
    onion, session_id, pub = data.decode().split("|")
    return onion, session_id, pub.encode()


def generate_qr_code(onion: str, session_id: str, rsa_bytes: bytes, root: tk.Tk) -> str:
    """Generate and optionally display a QR code containing encrypted connection info."""
    passphrase = simpledialog.askstring(
        "Input",
        "Enter passphrase for QR code encryption",
        parent=root,
        show="*",
    )
    if not passphrase:
        raise ValueError("Passphrase required")
    salt, nonce, ct, tag = encrypt_qr_data(onion, session_id, rsa_bytes, passphrase)
    qr_data = f"{salt.hex()}:{nonce.hex()}:{ct.hex()}:{tag.hex()}"
    if pyperclip:
        pyperclip.copy(qr_data)
    if qrcode:
        qr = qrcode.QRCode()
        qr.add_data(qr_data)
        qr.make()
        img = qr.make_image()
        photo = ImageTk.PhotoImage(img.resize((200, 200)))
        label = tk.Label(root, image=photo)
        label.image = photo
        label.pack(pady=10)
    return qr_data


def scan_qr_code(root: tk.Tk):
    """Scan a QR code from webcam or image and decrypt its payload."""
    if cv2 is None:
        return None, None, None
    cap = cv2.VideoCapture(0)
    if cap.isOpened():
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            codes = decode(frame)
            if codes:
                qr_data = codes[0].data.decode()
                cap.release()
                cv2.destroyAllWindows()
                try:
                    salt, nonce, ct, tag = [bytes.fromhex(x) for x in qr_data.split(":")]
                    passphrase = simpledialog.askstring(
                        "Input",
                        "Enter passphrase for QR code decryption",
                        parent=root,
                        show="*",
                    )
                    if not passphrase:
                        return None, None, None
                    return decrypt_qr_data(salt, nonce, ct, tag, passphrase)
                except Exception:
                    messagebox.showerror("Error", "Invalid QR code or passphrase")
                    return None, None, None
            cv2.imshow("QR Code Scanner", frame)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break
        cap.release()
        cv2.destroyAllWindows()
    qr_file = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg")])
    if qr_file:
        img = cv2.imread(qr_file)
        codes = decode(img)
        if codes:
            qr_data = codes[0].data.decode()
            try:
                salt, nonce, ct, tag = [bytes.fromhex(x) for x in qr_data.split(":")]
                passphrase = simpledialog.askstring(
                    "Input",
                    "Enter passphrase for QR code decryption",
                    parent=root,
                    show="*",
                )
                if not passphrase:
                    return None, None, None
                return decrypt_qr_data(salt, nonce, ct, tag, passphrase)
            except Exception:
                messagebox.showerror("Error", "Invalid QR code or passphrase")
    return None, None, None


def setup_hidden_service(port: int, use_stem: bool = False):
    """Create a Tor hidden service using torpy or stem with retries."""
    use_stem = use_stem or os.environ.get("ONIONCHAT_USE_STEM") == "1"
    if use_stem and Controller is not None:
        try:
            ctrl = Controller.from_port()
            ctrl.authenticate()
            hs = ctrl.create_ephemeral_hidden_service({80: port}, await_publication=True)

            class _Service:
                def __init__(self, controller, service_id):
                    self.controller = controller
                    self.service_id = service_id

                def close(self):
                    try:
                        self.controller.remove_ephemeral_hidden_service(self.service_id)
                    finally:
                        self.controller.close()

            return ctrl, _Service(ctrl, hs.service_id), f"{hs.service_id}.onion"
        except Exception as e:  # pragma: no cover - network dependency
            print(f"stem failed: {e}")

    for attempt in range(3):
        try:
            tor = TorClient()
            tor.get_circuit()
            onion = tor.create_hidden_service(ports={80: port})
            return tor, onion, onion.onion_hostname
        except Exception as e:  # pragma: no cover - network dependency
            print(f"Attempt {attempt+1} failed: {e}")
            if attempt == 2:
                raise Exception("Failed to create hidden service")
    raise Exception("Failed to create hidden service")
