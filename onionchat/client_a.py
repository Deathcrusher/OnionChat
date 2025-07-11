"""GUI and logic for hosting an OnionChat session (Client A)."""

import os
import socket
import threading
import time
import tempfile
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from queue import Queue


def _add_logo(root: tk.Tk) -> None:
    """Display the OnionChat logo if available."""
    logo_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "Logo", "onionchat_logo.png")
    )
    if os.path.exists(logo_path):
        try:
            logo_img = tk.PhotoImage(file=logo_path)
            root.logo_img = logo_img  # prevent garbage collection
            tk.Label(root, image=logo_img).pack(pady=5)
        except Exception:
            pass

from cryptography.hazmat.primitives import (
    hashes,
    padding as asym_padding,
    serialization,
)
from cryptography.hazmat.primitives import constant_time

from .chat_utils import (
    generate_keys,
    derive_session_key,
    encrypt_message,
    decrypt_message,
    encrypt_bytes,
    decrypt_bytes,
    generate_qr_code,
    setup_hidden_service,
    secure_wipe,
)


def _call_in_main(root: tk.Tk, func, *args, **kwargs):
    """Execute ``func`` in the Tkinter main thread and return its result."""
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


def client_a_main(args):
    """Launch the GUI server and wait for Client B to connect."""
    root = tk.Tk()
    root.title("Client A - Secure Chat")
    root.geometry("600x400")
    _add_logo(root)

    rsa_private, _, rsa_public_bytes, ecdh_private, ecdh_public_bytes = (
        generate_keys()
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp:
        tmp.write(rsa_public_bytes)
        public_key_path = tmp.name

    status = tk.Label(root, text="Starting Tor, please wait...")
    status.pack(pady=5)
    progress = ttk.Progressbar(root, mode="indeterminate")
    progress.pack(pady=5)
    progress.start()

    tor_data: dict[str, object] = {}

    def start_tor() -> None:
        try:
            tor_data["result"] = setup_hidden_service(
                args.port, args.tor_impl == "stem"
            )
        except Exception as exc:  # pragma: no cover - network dependency
            tor_data["error"] = exc

    threading.Thread(target=start_tor, daemon=True).start()

    def wait_for_tor() -> None:
        if "result" in tor_data:
            progress.stop()
            progress.pack_forget()
            status.config(text="Tor started")
            continue_setup(*tor_data["result"])
        elif "error" in tor_data:
            progress.stop()
            progress.pack_forget()
            messagebox.showerror(
                "Error",
                f"Failed to create hidden service: {tor_data['error']}",
            )
            root.destroy()
        else:
            root.after(100, wait_for_tor)

    def continue_setup(tor, onion, onion_hostname):
        session_id = os.urandom(32).hex()
        qr_data = generate_qr_code(
            onion_hostname, session_id, rsa_public_bytes, root
        )

        info_label = tk.Label(
            root,
            text=(
                f"Onion: {onion_hostname}\n"
                f"Session ID: {session_id}\n"
                f"Public Key: {public_key_path}\n"
                "QR Data: Copied to clipboard"
            ),
        )
        info_label.pack(pady=10)

        def copy_qr_data():
            from pyperclip import copy

            copy(qr_data)
            _call_in_main(
                root,
                messagebox.showinfo,
                "Info",
                "QR code data copied to clipboard",
            )

        tk.Button(root, text="Copy QR Data", command=copy_qr_data).pack(pady=5)

        chat_display = ScrolledText(root, height=15, width=60, state="disabled")
        chat_display.pack(pady=10)
        message_entry = tk.Entry(root, width=50)
        message_entry.pack(pady=5)
        message_entry.bind("<Return>", lambda _: send_message())

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("localhost", args.port))
        server.listen(1)
        server.setblocking(False)

        conn = None
        session_key = None
        last_activity = time.time()
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
                server.close()
            except Exception:
                pass
            try:
                onion.close()
            except Exception:
                pass
            try:
                tor.close()
            except Exception:
                pass
            if session_key:
                secure_wipe(session_key)
            secure_wipe(
                ecdh_private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            )
            secure_wipe(
                rsa_private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
            try:
                os.remove(public_key_path)
            except Exception:
                pass
            try:
                root.destroy()
            except Exception:
                pass

        def receive_messages():
            nonlocal last_activity
            receiving_file = False
            file_buffer = b""
            file_name = ""
            file_size = 0
            try:
                while True:
                    try:
                        data = _recv_packet(conn)
                        last_activity = time.time()
                        nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
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
                                        chat_display, chat_display.yview, tk.END
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
                                chat_display, chat_display.config, state="normal"
                            )
                            _call_in_main(
                                chat_display,
                                chat_display.insert,
                                tk.END,
                                f"Client B: {message}\n",
                            )
                            _call_in_main(
                                chat_display, chat_display.config, state="disabled"
                            )
                            _call_in_main(chat_display, chat_display.yview, tk.END)
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

        def terminate_session():
            """Send the termination signature and cleanup resources."""
            signature = rsa_private.sign(
                b"TERMINATE",
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            try:
                _send_packet(conn, signature)
            except Exception:
                pass
            cleanup()
            return

        def send_message():
            nonlocal last_activity
            message = message_entry.get()
            if not message:
                return
            if message.lower() == "exit":
                terminate_session()
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
                last_activity = time.time()
            except Exception as e:
                _call_in_main(
                    root, messagebox.showerror, "Error", f"Encryption failed: {e}"
                )
                cleanup()
            finally:
                message_entry.delete(0, tk.END)

        def send_file():
            nonlocal last_activity
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
                last_activity = time.time()
            except Exception as e:
                _call_in_main(
                    root,
                    messagebox.showerror,
                    "Error",
                    f"File transfer failed: {e}",
                )
                cleanup()

        def check_timeout():
            if conn and time.time() - last_activity > args.timeout:
                signature = rsa_private.sign(
                    b"TERMINATE",
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                try:
                    _send_packet(conn, signature)
                except Exception:
                    pass
                _call_in_main(
                    root, messagebox.showinfo, "Info", "Session timed out"
                )
                cleanup()
                return
            root.after(1000, check_timeout)

        tk.Button(root, text="Send", command=send_message).pack(pady=5)
        tk.Button(root, text="Send File", command=send_file).pack(pady=5)
        tk.Button(root, text="Exit", command=terminate_session).pack(pady=5)

        def accept_connection():
            nonlocal conn, session_key
            try:
                conn, _ = server.accept()
            except BlockingIOError:
                root.after(100, accept_connection)
                return
            try:
                received_session_id = _recv_exact(conn, len(session_id)).decode()
                if not constant_time.bytes_eq(
                    received_session_id.encode(), session_id.encode()
                ):
                    _call_in_main(
                        root, messagebox.showerror, "Error", "Invalid session ID"
                    )
                    cleanup()
                    return

                encrypted_key = _recv_exact(conn, 512)
                try:
                    ecdh_peer_bytes = rsa_private.decrypt(
                        encrypted_key,
                        asym_padding.OAEP(
                            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    session_key = derive_session_key(ecdh_private, ecdh_peer_bytes)
                except Exception as e:
                    _call_in_main(
                        root,
                        messagebox.showerror,
                        "Error",
                        f"Key exchange failed: {e}",
                    )
                    cleanup()
                    return

                conn.sendall(ecdh_public_bytes)
                threading.Thread(target=receive_messages, daemon=True).start()
                root.after(1000, check_timeout)
            except Exception as e:
                _call_in_main(
                    root, messagebox.showerror, "Error", f"Connection failed: {e}"
                )
                cleanup()
                return

        accept_connection()

    wait_for_tor()
    root.mainloop()

