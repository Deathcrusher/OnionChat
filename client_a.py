"""GUI and logic for hosting an OnionChat session (Client A)."""
import os
import socket
import threading
import time
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

from cryptography.hazmat.primitives import hashes, padding as asym_padding, serialization
from cryptography.hazmat.primitives import constant_time

from chat_utils import (
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


def client_a_main(args):
    """Launch the GUI server and wait for Client B to connect."""
    root = tk.Tk()
    root.title("Client A - Secure Chat")
    root.geometry("600x400")

    rsa_private, _, rsa_public_bytes, ecdh_private, ecdh_public_bytes = generate_keys()
    with open("client_a_public_key.pem", "wb") as f:
        f.write(rsa_public_bytes)

    status = tk.Label(root, text="Starting Tor, please wait...")
    status.pack(pady=5)
    root.update()
    try:
        tor, onion, onion_hostname = setup_hidden_service(args.port, args.tor_impl == "stem")
        status.config(text="Tor started")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to create hidden service: {e}")
        root.destroy()
        return
    session_id = os.urandom(32).hex()
    qr_data = generate_qr_code(onion_hostname, session_id, rsa_public_bytes, root)

    info_label = tk.Label(
        root,
        text=f"Onion: {onion_hostname}\nSession ID: {session_id}\nPublic Key: client_a_public_key.pem\nQR Data: Copied to clipboard",
    )
    info_label.pack(pady=10)

    def copy_qr_data():
        from pyperclip import copy
        copy(qr_data)
        messagebox.showinfo("Info", "QR code data copied to clipboard")

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

    def receive_messages():
        nonlocal last_activity
        receiving_file = False
        file_buffer = b""
        file_name = ""
        file_size = 0
        while True:
            try:
                data = conn.recv(4096)
                last_activity = time.time()
                if not data:
                    break
                nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
                if receiving_file:
                    try:
                        chunk = decrypt_bytes(nonce, ciphertext, tag, session_key)
                        file_buffer += chunk
                        if len(file_buffer) >= file_size:
                            save_path = filedialog.asksaveasfilename(initialfile=file_name)
                            if save_path:
                                with open(save_path, "wb") as f:
                                    f.write(file_buffer[:file_size])
                            chat_display.config(state="normal")
                            chat_display.insert(tk.END, f"Received file: {file_name}\n")
                            chat_display.config(state="disabled")
                            chat_display.yview(tk.END)
                            receiving_file = False
                            file_buffer = b""
                            file_name = ""
                            file_size = 0
                        continue
                    except Exception as e:
                        messagebox.showerror("Error", f"File transfer failed: {e}")
                        receiving_file = False
                        file_buffer = b""
                        file_name = ""
                        file_size = 0
                        continue
                try:
                    message = decrypt_message(nonce, ciphertext, tag, session_key)
                    if message.startswith("FILE_TRANSFER_START:"):
                        try:
                            _, fname, fsize = message.split(":", 2)
                            file_name = os.path.basename(fname)
                            file_size = int(fsize)
                            file_buffer = b""
                            receiving_file = True
                        except Exception as e:
                            messagebox.showerror("Error", f"Invalid file header: {e}")
                        continue
                    elif message == "FILE_TRANSFER_END":
                        receiving_file = False
                        file_buffer = b""
                        file_name = ""
                        file_size = 0
                        continue
                    chat_display.config(state="normal")
                    chat_display.insert(tk.END, f"Client B: {message}\n")
                    chat_display.config(state="disabled")
                    chat_display.yview(tk.END)
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {e}")
            except Exception:
                break
        if conn:
            conn.close()

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
            conn.send(signature)
        except Exception:
            pass
        conn.close()
        server.close()
        onion.close()
        tor.close()
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
            os.remove("client_a_public_key.pem")
        except Exception:
            pass
        root.destroy()
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
            nonce, ciphertext, tag = encrypt_message(message, session_key, args.padding)
            conn.send(nonce + tag + ciphertext)
            chat_display.config(state="normal")
            chat_display.insert(tk.END, f"You: {message}\n")
            chat_display.config(state="disabled")
            chat_display.yview(tk.END)
            message_entry.delete(0, tk.END)
            last_activity = time.time()
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def send_file():
        nonlocal last_activity
        file_path = filedialog.askopenfilename()
        if not file_path or not os.path.isfile(file_path):
            return
        if os.path.getsize(file_path) > args.max_file_size * 1024 * 1024:
            messagebox.showerror(
                "Error", f"File exceeds {args.max_file_size} MB limit"
            )
            return
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            filename = os.path.basename(file_path)
            header = f"FILE_TRANSFER_START:{filename}:{len(data)}"
            nonce, ciphertext, tag = encrypt_message(header, session_key, args.padding)
            conn.send(nonce + tag + ciphertext)
            chunk_size = 2048
            for i in range(0, len(data), chunk_size):
                chunk = data[i : i + chunk_size]
                n, c, t = encrypt_bytes(chunk, session_key)
                conn.send(n + t + c)
            nonce, ciphertext, tag = encrypt_message("FILE_TRANSFER_END", session_key, args.padding)
            conn.send(nonce + tag + ciphertext)
            chat_display.config(state="normal")
            chat_display.insert(tk.END, f"Sent file: {filename}\n")
            chat_display.config(state="disabled")
            chat_display.yview(tk.END)
            last_activity = time.time()
        except Exception as e:
            messagebox.showerror("Error", f"File transfer failed: {e}")

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
            conn.send(signature)
            conn.close()
            server.close()
            onion.close()
            tor.close()
            secure_wipe(session_key)
            secure_wipe(ecdh_private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ))
            secure_wipe(rsa_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
            try:
                os.remove("client_a_public_key.pem")
            except Exception:
                pass
            messagebox.showinfo("Info", "Session timed out")
            root.destroy()
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
            received_session_id = conn.recv(1024).decode()
            if not constant_time.bytes_eq(received_session_id.encode(), session_id.encode()):
                messagebox.showerror("Error", "Invalid session ID")
                conn.close()
                server.close()
                onion.close()
                tor.close()
                secure_wipe(session_key)
                secure_wipe(ecdh_private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                ))
                secure_wipe(rsa_private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))
                root.destroy()
                return

            encrypted_key = conn.recv(4096)
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
                messagebox.showerror("Error", f"Key exchange failed: {e}")
                conn.close()
                server.close()
                onion.close()
                tor.close()
                secure_wipe(session_key)
                secure_wipe(ecdh_private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                ))
                secure_wipe(rsa_private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))
                root.destroy()
                return

            conn.send(ecdh_public_bytes)
            threading.Thread(target=receive_messages, daemon=True).start()
            root.after(1000, check_timeout)
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            server.close()
            onion.close()
            tor.close()
            secure_wipe(session_key)
            secure_wipe(ecdh_private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ))
            secure_wipe(rsa_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
            root.destroy()
            return

    accept_connection()
    root.mainloop()
