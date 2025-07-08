"""GUI for connecting to an OnionChat session as Client B."""

import os
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from queue import Queue

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    padding as asym_padding,
    x25519,
)

from .chat_utils import (
    derive_session_key,
    encrypt_message,
    decrypt_message,
    encrypt_bytes,
    decrypt_bytes,
    scan_qr_code,
    secure_wipe,
)

from torpy import TorClient

try:
    from stem.control import Controller
except Exception:  # pragma: no cover - optional dependency
    Controller = None

try:
    import socks
except Exception:  # pragma: no cover - optional dependency
    socks = None


def _call_in_main(root: tk.Tk, func, *args, **kwargs):
    q: Queue = Queue(maxsize=1)

    def wrapper():
        try:
            q.put(func(*args, **kwargs))
        except Exception as exc:  # pragma: no cover - GUI errors
            q.put(exc)

    root.after(0, wrapper)
    result = q.get()
    if isinstance(result, Exception):
        raise result
    return result


def _send_packet(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(len(payload).to_bytes(4, "big") + payload)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def _recv_packet(sock: socket.socket) -> bytes:
    length = int.from_bytes(_recv_exact(sock, 4), "big")
    return _recv_exact(sock, length)


def client_b_main(
    onion_hostname: str, session_id: str, public_key_file: str, args
):
    """Connect to Client A using the supplied credentials."""
    root = tk.Tk()
    root.title("Client B - Secure Chat")
    root.geometry("600x400")

    try:
        with open(public_key_file, "rb") as f:
            rsa_public_bytes = f.read()
        rsa_public_key = serialization.load_pem_public_key(rsa_public_bytes)
    except Exception as e:
        _call_in_main(
            root,
            messagebox.showerror,
            "Error",
            f"Failed to load public key: {e}",
        )
        secure_wipe(
            rsa_public_bytes if "rsa_public_bytes" in locals() else b""
        )
        root.destroy()
        return

    ecdh_private_key = x25519.X25519PrivateKey.generate()
    ecdh_public_bytes = ecdh_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    encrypted_key = rsa_public_key.encrypt(
        ecdh_public_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    status = tk.Label(root, text="Connecting to Tor service...")
    status.pack(pady=5)
    root.update()
    use_stem = (
        args.tor_impl == "stem" or os.environ.get("ONIONCHAT_USE_STEM") == "1"
    )
    tor = None
    conn = None
    session_key = None
    cleanup_called = False

    def cleanup():
        nonlocal cleanup_called
        if cleanup_called:
            return
        cleanup_called = True
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        try:
            if tor:
                tor.close()
        except Exception:
            pass
        if session_key:
            secure_wipe(session_key)
        secure_wipe(
            ecdh_private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        if public_key_file == "temp_public_key.pem" and os.path.exists(
            public_key_file
        ):
            try:
                os.remove(public_key_file)
            except Exception:
                pass
        try:
            root.destroy()
        except Exception:
            pass

    try:
        if use_stem and Controller is not None and socks is not None:
            try:
                tor = Controller.from_port()
                tor.authenticate()
            except Exception as e:
                messagebox.showerror(
                    "Error",
                    f"Failed to connect to Tor controller: {e}",
                )
                cleanup()
                return
            try:
                conn = socks.socksocket()
                conn.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
                conn.connect((onion_hostname, 80))
            except Exception as e:
                messagebox.showerror(
                    "Error",
                    f"Failed to connect to Tor SOCKS proxy: {e}",
                )
                cleanup()
                return
        else:
            try:
                tor = TorClient()
                conn = tor.connect(onion_hostname, 80)
            except Exception as e:
                messagebox.showerror(
                    "Error",
                    f"Failed to connect to Tor service via Torpy: {e}",
                )
                cleanup()
                return
        status.config(text="Connected")
    except Exception as e:
        messagebox.showerror(
            "Error",
            f"An unexpected error occurred during Tor connection: {e}",
        )
        cleanup()
        return

    try:
        conn.sendall(session_id.encode())
        conn.sendall(encrypted_key)
        ecdh_peer_bytes = _recv_exact(conn, 32)
        session_key = derive_session_key(ecdh_private_key, ecdh_peer_bytes)
    except Exception as e:
        _call_in_main(
            root,
            messagebox.showerror,
            "Error",
            f"Session key derivation failed: {e}",
        )
        cleanup()
        return

    chat_display = ScrolledText(root, height=15, width=60, state="disabled")
    chat_display.pack(pady=10)
    message_entry = tk.Entry(root, width=50)
    message_entry.pack(pady=5)
    message_entry.bind("<Return>", lambda _: send_message())

    def receive_messages():
        receiving_file = False
        file_buffer = b""
        file_name = ""
        file_size = 0
        try:
            while True:
                try:
                    data = _recv_packet(conn)
                    if not data:
                        break
                    try:
                        rsa_public_key.verify(
                            data,
                            b"TERMINATE",
                            asym_padding.PSS(
                                mgf=asym_padding.MGF1(hashes.SHA256()),
                                salt_length=asym_padding.PSS.MAX_LENGTH,
                            ),
                        )
                        _call_in_main(
                            root,
                            messagebox.showinfo,
                            "Info",
                            "Session terminated by Client A",
                        )
                        cleanup()
                        return
                    except Exception:
                        nonce, tag, ciphertext = (
                            data[:12],
                            data[12:28],
                            data[28:],
                        )
                        if receiving_file:
                            try:
                                chunk = decrypt_bytes(
                                    nonce, ciphertext, tag, session_key
                                )
                                file_buffer += chunk
                                if len(file_buffer) >= file_size:
                                    save_path = _call_in_main(
                                        root,
                                        filedialog.asksaveasfilename,
                                        initialfile=file_name,
                                    )
                                    if save_path:
                                        with open(save_path, "wb") as f:
                                            f.write(file_buffer[:file_size])
                                    _call_in_main(
                                        chat_display,
                                        chat_display.config,
                                        state="normal",
                                    )
                                    _call_in_main(
                                        chat_display,
                                        chat_display.insert,
                                        tk.END,
                                        f"Received file: {file_name}\n",
                                    )
                                    _call_in_main(
                                        chat_display,
                                        chat_display.config,
                                        state="disabled",
                                    )
                                    _call_in_main(
                                        chat_display,
                                        chat_display.yview,
                                        tk.END,
                                    )
                                    receiving_file = False
                                    file_buffer = b""
                                    file_name = ""
                                    file_size = 0
                                continue
                            except Exception as e:
                                _call_in_main(
                                    root,
                                    messagebox.showerror,
                                    "Error",
                                    f"File transfer failed: {e}",
                                )
                                receiving_file = False
                                file_buffer = b""
                                file_name = ""
                                file_size = 0
                                continue
                        try:
                            message = decrypt_message(
                                nonce, ciphertext, tag, session_key
                            )
                            if message.startswith("FILE_TRANSFER_START:"):
                                try:
                                    _, fname, fsize = message.split(":", 2)
                                    file_name = os.path.basename(fname)
                                    file_size = int(fsize)
                                    file_buffer = b""
                                    receiving_file = True
                                except Exception as e:
                                    _call_in_main(
                                        root,
                                        messagebox.showerror,
                                        "Error",
                                        f"Invalid file header: {e}",
                                    )
                                continue
                            elif message == "FILE_TRANSFER_END":
                                receiving_file = False
                                file_buffer = b""
                                file_name = ""
                                file_size = 0
                                continue
                            _call_in_main(
                                chat_display,
                                chat_display.config,
                                state="normal",
                            )
                            _call_in_main(
                                chat_display,
                                chat_display.insert,
                                tk.END,
                                f"Client A: {message}\n",
                            )
                            _call_in_main(
                                chat_display,
                                chat_display.config,
                                state="disabled",
                            )
                            _call_in_main(
                                chat_display, chat_display.yview, tk.END
                            )
                        except Exception as e:
                            _call_in_main(
                                root,
                                messagebox.showerror,
                                "Error",
                                f"Decryption failed: {e}",
                            )
                except Exception:
                    break
        finally:
            cleanup()

    def send_message():
        message = message_entry.get()
        if not message:
            return
        try:
            nonce, ciphertext, tag = encrypt_message(
                message, session_key, args.padding
            )
            _send_packet(conn, nonce + tag + ciphertext)
            _call_in_main(chat_display, chat_display.config, state="normal")
            _call_in_main(
                chat_display, chat_display.insert, tk.END, f"You: {message}\n"
            )
            _call_in_main(chat_display, chat_display.config, state="disabled")
            _call_in_main(chat_display, chat_display.yview, tk.END)
        except Exception as e:
            _call_in_main(
                root,
                messagebox.showerror,
                "Error",
                f"Sending message failed: {e}",
            )
            cleanup()
        finally:
            message_entry.delete(0, tk.END)

    def send_file():
        file_path = _call_in_main(root, filedialog.askopenfilename)
        if not file_path or not os.path.isfile(file_path):
            return
        if os.path.getsize(file_path) > args.max_file_size * 1024 * 1024:
            _call_in_main(
                root,
                messagebox.showerror,
                "Error",
                f"File exceeds {args.max_file_size} MB limit",
            )
            return
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            filename = os.path.basename(file_path)
            header = f"FILE_TRANSFER_START:{filename}:{len(data)}"
            nonce, ciphertext, tag = encrypt_message(
                header, session_key, args.padding
            )
            _send_packet(conn, nonce + tag + ciphertext)
            chunk_size = 2048
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                n, c, t = encrypt_bytes(chunk, session_key)
                _send_packet(conn, n + t + c)
            nonce, ciphertext, tag = encrypt_message(
                "FILE_TRANSFER_END", session_key, args.padding
            )
            _send_packet(conn, nonce + tag + ciphertext)
            _call_in_main(chat_display, chat_display.config, state="normal")
            _call_in_main(
                chat_display,
                chat_display.insert,
                tk.END,
                f"Sent file: {filename}\n",
            )
            _call_in_main(chat_display, chat_display.config, state="disabled")
            _call_in_main(chat_display, chat_display.yview, tk.END)
        except Exception as e:
            _call_in_main(
                root,
                messagebox.showerror,
                "Error",
                f"File transfer failed: {e}",
            )
            cleanup()

    tk.Button(root, text="Send", command=send_message).pack(pady=5)
    tk.Button(root, text="Send File", command=send_file).pack(pady=5)
    threading.Thread(target=receive_messages, daemon=True).start()
    try:
        root.mainloop()
    finally:
        cleanup()


def client_b_setup(args):
    """Prompt the user for connection credentials or scan a QR code."""
    root = tk.Tk()
    root.title("Client B Setup")
    root.geometry("400x300")

    tk.Label(root, text="Onion Address:").pack(pady=5)
    onion_entry = tk.Entry(root, width=50)
    onion_entry.insert(0, args.onion if hasattr(args, "onion") else "")
    onion_entry.pack(pady=5)

    tk.Label(root, text="Session ID:").pack(pady=5)
    session_entry = tk.Entry(root, width=50)
    session_entry.insert(0, args.session if hasattr(args, "session") else "")
    session_entry.pack(pady=5)

    tk.Label(root, text="Public Key File:").pack(pady=5)
    key_entry = tk.Entry(root, width=50)
    key_entry.insert(0, str(args.key) if hasattr(args, "key") else "")
    key_entry.pack(pady=5)

    def browse_file():
        """Select a public key file and populate the entry."""
        key_entry.delete(0, tk.END)
        key_entry.insert(0, filedialog.askopenfilename())

    tk.Button(root, text="Browse", command=browse_file).pack(pady=5)

    def scan_and_fill():
        onion_hostname, session_id, public_key = scan_qr_code(root)
        if onion_hostname and session_id and public_key:
            onion_entry.delete(0, tk.END)
            onion_entry.insert(0, onion_hostname)
            session_entry.delete(0, tk.END)
            session_entry.insert(0, session_id)
            with open("temp_public_key.pem", "wb") as f:
                f.write(public_key)
            key_entry.delete(0, tk.END)
            key_entry.insert(0, "temp_public_key.pem")
        else:
            _call_in_main(
                root, messagebox.showerror, "Error", "Failed to scan QR code"
            )

    tk.Button(root, text="Scan QR Code", command=scan_and_fill).pack(pady=5)

    def start_client_b():
        onion = onion_entry.get()
        session = session_entry.get()
        key_file = key_entry.get()
        if not (onion and session and key_file):
            _call_in_main(
                root, messagebox.showerror, "Error", "All fields are required"
            )
            return
        root.destroy()
        client_b_main(onion, session, key_file, args)

    tk.Button(root, text="Connect", command=start_client_b).pack(pady=10)
    root.mainloop()
