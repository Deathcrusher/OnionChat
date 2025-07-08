"""Shared utilities for OnionChat.

This module provides crypto operations, QR code handling and Tor hidden service
setup helpers.
"""

import os
import platform
import secrets
import tarfile
import urllib.request
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import ImageTk

try:
    from _wiper import wipe as c_wipe
except Exception:  # pragma: no cover - optional C module
    c_wipe = None

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


TOR_VERSION = "14.5.4"
TOR_BASE_URL = f"https://dist.torproject.org/torbrowser/{TOR_VERSION}/"


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
        if c_wipe is not None:
            c_wipe(ba)
        else:
            rnd = secrets.token_bytes(len(ba))
            for i in range(len(ba)):
                ba[i] = rnd[i]
            for i in range(len(ba)):
                ba[i] = 0
    except Exception:
        pass


def _download_tor_bundle(dest_dir: str) -> str | None:
    """Download and extract a Tor expert bundle for the current platform."""
    system = platform.system()
    machine = platform.machine()
    bundle_map = {
        ("Windows", "AMD64"): f"tor-expert-bundle-windows-x86_64-{TOR_VERSION}.tar.gz",
        ("Windows", "x86"): f"tor-expert-bundle-windows-i686-{TOR_VERSION}.tar.gz",
        ("Linux", "x86_64"): f"tor-expert-bundle-linux-x86_64-{TOR_VERSION}.tar.gz",
        ("Linux", "i686"): f"tor-expert-bundle-linux-i686-{TOR_VERSION}.tar.gz",
        ("Darwin", "x86_64"): f"tor-expert-bundle-macos-x86_64-{TOR_VERSION}.tar.gz",
        ("Darwin", "arm64"): f"tor-expert-bundle-macos-aarch64-{TOR_VERSION}.tar.gz",
    }
    file_name = bundle_map.get((system, machine))
    if not file_name:
        return None
    url = TOR_BASE_URL + file_name
    archive = os.path.join(dest_dir, file_name)
    try:
        if not os.path.exists(archive):
            urllib.request.urlretrieve(url, archive)
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(dest_dir)
        bundle_dir = os.path.join(dest_dir, file_name[:-7])
        tor_bin = os.path.join(
            bundle_dir,
            "Tor",
            "tor.exe" if system == "Windows" else "tor",
        )
        if os.path.exists(tor_bin):
            os.chmod(tor_bin, 0o755)
            return tor_bin
    except Exception:
        return None
    return None


def _ensure_tor() -> str | None:
    """Return path to Tor, downloading a bundle if necessary."""
    tor_dir = os.path.join(os.path.dirname(__file__), "..", "tor_files")
    os.makedirs(tor_dir, exist_ok=True)
    tor_path = os.environ.get("TOR_PATH")
    if tor_path and os.path.exists(tor_path):
        return tor_path
    candidate = os.path.join(
        tor_dir,
        "Tor",
        "tor.exe" if os.name == "nt" else "tor",
    )
    if os.path.exists(candidate):
        return candidate
    if os.name == "nt":
        for path in [
            os.path.expanduser("~/Desktop/Tor Browser/Browser/TorBrowser/tor.exe"),
            "C:\\Program Files\\Tor Browser\\Browser\\TorBrowser\\tor.exe",
            "C:\\Tor Browser\\Browser\\TorBrowser\\tor.exe",
        ]:
            if os.path.exists(path):
                return path
    return _download_tor_bundle(tor_dir)


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
        encoding=serialization.Encoding.Raw,
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


def encrypt_qr_data(
    onion: str, session_id: str, rsa_bytes: bytes, passphrase: str
):
    """Encrypt connection info for QR code transfer."""
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
    )
    key = kdf.derive(passphrase.encode())
    payload = f"{onion}|{session_id}|{rsa_bytes.decode()}".encode()
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    enc = cipher.encryptor()
    ct = enc.update(payload) + enc.finalize()
    return salt, nonce, ct, enc.tag


def decrypt_qr_data(
    salt: bytes, nonce: bytes, ct: bytes, tag: bytes, passphrase: str
):
    """Decrypt QR code data using the provided passphrase."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
    )
    key = kdf.derive(passphrase.encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    dec = cipher.decryptor()
    data = dec.update(ct) + dec.finalize()
    onion, session_id, pub = data.decode().split("|")
    return onion, session_id, pub.encode()


def generate_qr_code(
    onion: str, session_id: str, rsa_bytes: bytes, root: tk.Tk
) -> str:
    """Generate and optionally display a QR code.

    The QR code contains encrypted connection info.
    """
    passphrase = simpledialog.askstring(
        "Input",
        "Enter passphrase for QR code encryption",
        parent=root,
        show="*",
    )
    if not passphrase:
        raise ValueError("Passphrase required")
    salt, nonce, ct, tag = encrypt_qr_data(
        onion, session_id, rsa_bytes, passphrase
    )
    qr_data = f"{salt.hex()}:{nonce.hex()}:{ct.hex()}:{tag.hex()}"
    if pyperclip:
        try:
            pyperclip.copy(qr_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy QR data to clipboard: {e}")
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
                    salt, nonce, ct, tag = [
                        bytes.fromhex(x) for x in qr_data.split(":")
                    ]
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
                    messagebox.showerror(
                        "Error", "Invalid QR code or passphrase"
                    )
                    return None, None, None
            cv2.imshow("QR Code Scanner", frame)
            if cv2.waitKey(1) & 0xFF == ord("q"):
                break
        cap.release()
        cv2.destroyAllWindows()
    qr_file = filedialog.askopenfilename(
        filetypes=[("Image files", "*.png *.jpg")]
    )
    if qr_file:
        img = cv2.imread(qr_file)
        codes = decode(img)
        if codes:
            qr_data = codes[0].data.decode()
            try:
                salt, nonce, ct, tag = [
                    bytes.fromhex(x) for x in qr_data.split(":")
                ]
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
    """Create a Tor hidden service using ``stem``.

    If a Tor control connection cannot be established, the function tries to
    start a Tor process automatically using ``stem.process``. It also attempts
    to install ``stem`` on the fly if the module is missing. This provides a
    best effort so users do not need to start Tor manually.
    """
    use_stem = use_stem or os.environ.get("ONIONCHAT_USE_STEM") == "1"

    if not use_stem:
        raise RuntimeError(
            "torpy does not support hidden services; use --tor-impl stem"
        )

    # Attempt to import required stem modules, installing them if necessary.
    try:
        from stem.control import Controller  # type: ignore
        from stem.process import launch_tor_with_config  # type: ignore
    except Exception:  # pragma: no cover - network dependency
        try:
            import subprocess
            import sys

            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "stem"]
            )
            from stem.control import Controller  # type: ignore
            from stem.process import launch_tor_with_config  # type: ignore
        except Exception as e:  # pragma: no cover - network dependency
            raise RuntimeError(
                "stem is required to create hidden services"
            ) from e

    tor_process = None
    tor_path = _ensure_tor() or "tor"

    try:
        try:
            ctrl = Controller.from_port()
            ctrl.authenticate()
        except Exception:
            tor_process = launch_tor_with_config(
                config={"ControlPort": "9051", "SOCKSPort": "9050"},
                tor_cmd=tor_path,

            )
            ctrl = Controller.from_port()
            ctrl.authenticate()

        hs = ctrl.create_ephemeral_hidden_service(
            {80: port}, await_publication=True, timeout=60
        )

        class _Service:
            def __init__(self, controller, service_id, process):
                self.controller = controller
                self.service_id = service_id
                self.process = process

            def close(self):  # pragma: no cover - cleanup code
                try:
                    self.controller.remove_ephemeral_hidden_service(
                        self.service_id
                    )
                finally:
                    try:
                        self.controller.close()
                    finally:
                        if self.process:
                            try:
                                self.process.kill()
                            except Exception:
                                pass

        return (
            ctrl,
            _Service(ctrl, hs.service_id, tor_process),
            f"{hs.service_id}.onion",
        )
    except FileNotFoundError as e:  # pragma: no cover - tor missing
        if tor_process:
            try:
                tor_process.kill()
            except Exception:
                pass
        raise RuntimeError(
            "Tor executable not found. Automatic download failed; install Tor or set TOR_PATH"
        ) from e
    except Exception as e:  # pragma: no cover - network dependency
        if tor_process:
            try:
                tor_process.kill()
            except Exception:
                pass
        raise RuntimeError(f"Failed to create hidden service using stem: {e}")
