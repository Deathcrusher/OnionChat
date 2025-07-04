#!/usr/bin/env python3
import os
import sys
import socket
import threading
import secrets
import subprocess
import time
import argparse
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import constant_time
from PIL import Image, ImageTk
try:
    from torpy import TorClient
    from torpy.hiddenservice import HiddenService
except ImportError:
    print("Installing torpy...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "torpy"])
    from torpy import TorClient
    from torpy.hiddenservice import HiddenService
try:
    from cryptography import hazmat
except ImportError:
    print("Installing cryptography...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography import hazmat
try:
    import qrcode
except ImportError:
    print("Installing qrcode...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "qrcode"])
    import qrcode
try:
    from pyzbar.pyzbar import decode
    import cv2
except ImportError:
    print("Installing pyzbar and opencv-python...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyzbar", "opencv-python"])
    from pyzbar.pyzbar import decode
    import cv2
try:
    import pyperclip
except ImportError:
    print("Installing pyperclip...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyperclip"])
    import pyperclip
try:
    from PIL import Image, ImageTk
except ImportError:
    print("Installing Pillow...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Pillow"])
    from PIL import Image, ImageTk

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Secure Chat Messenger with GUI")
parser.add_argument("mode", choices=["client_a", "client_b"], help="Run as client_a or client_b")
parser.add_argument("--port", type=int, default=12345, help="Port for hidden service")
parser.add_argument("--timeout", type=int, default=600, help="Session timeout in seconds")
parser.add_argument("--padding", type=int, default=1024, help="Message padding length")
args = parser.parse_args()

# Generate RSA and ECDH key pairs
def generate_keys():
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    rsa_public_key = rsa_private_key.public_key()
    rsa_public_key_bytes = rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ecdh_private_key = x25519.X25519PrivateKey.generate()
    ecdh_public_key = ecdh_private_key.public_key()
    ecdh_public_key_bytes = ecdh_public_key.public_bytes(
        encoding=serialization.Raw,
        format=serialization.PublicFormat.Raw
    )
    return rsa_private_key, rsa_public_key, rsa_public_key_bytes, ecdh_private_key, ecdh_public_key_bytes

# Derive session key using ECDH
def derive_session_key(ecdh_private_key, ecdh_peer_public_key_bytes):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(ecdh_peer_public_key_bytes)
    shared_key = ecdh_private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chat_session"
    ).derive(shared_key)

# AES encryption/decryption with padding
def encrypt_message(message, key):
    message_bytes = message.encode()
    length = len(message_bytes)
    if length + 4 > args.padding:
        raise ValueError("Message too long for padding")
    padding = secrets.token_bytes(args.padding - length - 4)
    padded_message = length.to_bytes(4, 'big') + message_bytes + padding
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

def decrypt_message(nonce, ciphertext, tag, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    length = int.from_bytes(padded_message[:4], 'big')
    return padded_message[4:4+length].decode()

# Encrypt/decrypt raw bytes for file transfer
def encrypt_bytes(data, key):
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

def decrypt_bytes(nonce, ciphertext, tag, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Encrypt/decrypt QR code data
def encrypt_qr_data(onion_hostname, session_id, rsa_public_key_bytes, passphrase):
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(passphrase.encode())
    data = f"{onion_hostname}|{session_id}|{rsa_public_key_bytes.decode()}".encode()
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return salt, nonce, ciphertext, encryptor.tag

def decrypt_qr_data(salt, nonce, ciphertext, tag, passphrase):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(passphrase.encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    onion_hostname, session_id, public_key = data.decode().split("|")
    return onion_hostname, session_id, public_key.encode()

# Generate QR code in memory
def generate_qr_code(onion_hostname, session_id, rsa_public_key_bytes, root):
    passphrase = simpledialog.askstring("Input", "Enter passphrase for QR code encryption", parent=root)
    if not passphrase:
        raise ValueError("Passphrase required")
    salt, nonce, ciphertext, tag = encrypt_qr_data(onion_hostname, session_id, rsa_public_key_bytes, passphrase)
    qr_data = f"{salt.hex()}:{nonce.hex()}:{ciphertext.hex()}:{tag.hex()}"
    pyperclip.copy(qr_data)
    qr = qrcode.QRCode()
    qr.add_data(qr_data)
    qr.make()
    qr_img = qr.make_image()
    qr_photo = ImageTk.PhotoImage(qr_img.resize((200, 200)))
    qr_label = tk.Label(root, image=qr_photo)
    qr_label.image = qr_photo
    qr_label.pack(pady=10)
    return qr_data

# Scan QR code
def scan_qr_code(root):
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
                    salt, nonce, ciphertext, tag = [bytes.fromhex(x) for x in qr_data.split(":")]
                    passphrase = simpledialog.askstring("Input", "Enter passphrase for QR code decryption", parent=root)
                    if not passphrase:
                        return None, None, None
                    return decrypt_qr_data(salt, nonce, ciphertext, tag, passphrase)
                except:
                    messagebox.showerror("Error", "Invalid QR code or passphrase")
                    return None, None, None
            cv2.imshow("QR Code Scanner", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
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
                salt, nonce, ciphertext, tag = [bytes.fromhex(x) for x in qr_data.split(":")]
                passphrase = simpledialog.askstring("Input", "Enter passphrase for QR code decryption", parent=root)
                if not passphrase:
                    return None, None, None
                return decrypt_qr_data(salt, nonce, ciphertext, tag, passphrase)
            except:
                messagebox.showerror("Error", "Invalid QR code or passphrase")
    return None, None, None

# Setup Tor hidden service
def setup_hidden_service():
    for attempt in range(3):
        try:
            tor = TorClient()
            tor.get_circuit()
            onion = tor.create_hidden_service(ports={80: args.port})
            return tor, onion, onion.onion_hostname
        except Exception as e:
            print(f"Attempt {attempt+1} failed: {e}")
            if attempt == 2:
                raise Exception("Failed to create hidden service")
    raise Exception("Failed to create hidden service")

# Client A: GUI
def client_a_main():
    root = tk.Tk()
    root.title("Client A - Secure Chat")
    root.geometry("600x400")

    rsa_private_key, _, rsa_public_key_bytes, ecdh_private_key, ecdh_public_key_bytes = generate_keys()
    with open("client_a_public_key.pem", "wb") as f:
        f.write(rsa_public_key_bytes)

    try:
        tor, onion, onion_hostname = setup_hidden_service()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to create hidden service: {e}")
        root.destroy()
        return
    session_id = secrets.token_bytes(32).hex()
    qr_data = generate_qr_code(onion_hostname, session_id, rsa_public_key_bytes, root)

    info_label = tk.Label(root, text=f"Onion: {onion_hostname}\nSession ID: {session_id}\nPublic Key: client_a_public_key.pem\nQR Data: Copied to clipboard")
    info_label.pack(pady=10)

    def copy_qr_data():
        pyperclip.copy(qr_data)
        messagebox.showinfo("Info", "QR code data copied to clipboard")

    tk.Button(root, text="Copy QR Data", command=copy_qr_data).pack(pady=5)

    chat_display = tk.Text(root, height=15, width=60, state='disabled')
    chat_display.pack(pady=10)
    message_entry = tk.Entry(root, width=50)
    message_entry.pack(pady=5)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('localhost', args.port))
    server.listen(1)

    conn = None
    session_key = None
    last_activity = time.time()

    def receive_messages():
        nonlocal last_activity, conn
        receiving_file = False
        file_buffer = b''
        file_name = ''
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
                                with open(save_path, 'wb') as f:
                                    f.write(file_buffer[:file_size])
                            chat_display.config(state='normal')
                            chat_display.insert(tk.END, f"Received file: {file_name}\n")
                            chat_display.config(state='disabled')
                            chat_display.see(tk.END)
                            receiving_file = False
                            file_buffer = b''
                            file_name = ''
                            file_size = 0
                        continue
                    except Exception as e:
                        messagebox.showerror("Error", f"File transfer failed: {e}")
                        receiving_file = False
                        file_buffer = b''
                        file_name = ''
                        file_size = 0
                        continue
                try:
                    message = decrypt_message(nonce, ciphertext, tag, session_key)
                    if message.startswith("FILE_TRANSFER_START:"):
                        try:
                            _, fname, fsize = message.split(":", 2)
                            file_name = os.path.basename(fname)
                            file_size = int(fsize)
                            file_buffer = b''
                            receiving_file = True
                        except Exception as e:
                            messagebox.showerror("Error", f"Invalid file header: {e}")
                        continue
                    elif message == "FILE_TRANSFER_END":
                        receiving_file = False
                        file_buffer = b''
                        file_name = ''
                        file_size = 0
                        continue
                    chat_display.config(state='normal')
                    chat_display.insert(tk.END, f"Client B: {message}\n")
                    chat_display.config(state='disabled')
                    chat_display.see(tk.END)
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {e}")
            except:
                break
        if conn:
            conn.close()

    def send_message():
        nonlocal last_activity, conn, session_key
        message = message_entry.get()
        if not message:
            return
        if message.lower() == 'exit':
            signature = rsa_private_key.sign(
                b"TERMINATE",
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
            )
            conn.send(signature)
            conn.close()
            server.close()
            onion.close()
            tor.close()
            try:
                os.remove("client_a_public_key.pem")
            except:
                pass
            root.destroy()
            return
        try:
            nonce, ciphertext, tag = encrypt_message(message, session_key)
            conn.send(nonce + tag + ciphertext)
            chat_display.config(state='normal')
            chat_display.insert(tk.END, f"You: {message}\n")
            chat_display.config(state='disabled')
            chat_display.see(tk.END)
            message_entry.delete(0, tk.END)
            last_activity = time.time()
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def send_file():
        nonlocal last_activity, conn, session_key
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            filename = os.path.basename(file_path)
            header = f"FILE_TRANSFER_START:{filename}:{len(data)}"
            nonce, ciphertext, tag = encrypt_message(header, session_key)
            conn.send(nonce + tag + ciphertext)
            chunk_size = 2048
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                n, c, t = encrypt_bytes(chunk, session_key)
                conn.send(n + t + c)
            nonce, ciphertext, tag = encrypt_message("FILE_TRANSFER_END", session_key)
            conn.send(nonce + tag + ciphertext)
            chat_display.config(state='normal')
            chat_display.insert(tk.END, f"Sent file: {filename}\n")
            chat_display.config(state='disabled')
            chat_display.see(tk.END)
            last_activity = time.time()
        except Exception as e:
            messagebox.showerror("Error", f"File transfer failed: {e}")

    def check_timeout():
        nonlocal last_activity, conn
        if conn and time.time() - last_activity > args.timeout:
            signature = rsa_private_key.sign(
                b"TERMINATE",
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
            )
            conn.send(signature)
            conn.close()
            server.close()
            onion.close()
            tor.close()
            try:
                os.remove("client_a_public_key.pem")
            except:
                pass
            messagebox.showinfo("Info", "Session timed out")
            root.destroy()
        root.after(1000, check_timeout)

    tk.Button(root, text="Send", command=send_message).pack(pady=5)
    tk.Button(root, text="Send File", command=send_file).pack(pady=5)
    tk.Button(root, text="Exit", command=lambda: send_message('exit')).pack(pady=5)

    try:
        conn, addr = server.accept()
        received_session_id = conn.recv(1024).decode()
        if not constant_time.bytes_eq(received_session_id.encode(), session_id.encode()):
            messagebox.showerror("Error", "Invalid session ID")
            conn.close()
            server.close()
            onion.close()
            tor.close()
            root.destroy()
            return

        encrypted_key = conn.recv(4096)
        try:
            ecdh_peer_public_key_bytes = rsa_private_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            session_key = derive_session_key(ecdh_private_key, ecdh_peer_public_key_bytes)
        except Exception as e:
            messagebox.showerror("Error", f"Key exchange failed: {e}")
            conn.close()
            server.close()
            onion.close()
            tor.close()
            root.destroy()
            return

        conn.send(ecdh_public_key_bytes)
        threading.Thread(target=receive_messages, daemon=True).start()
        root.after(1000, check_timeout)
    except Exception as e:
        messagebox.showerror("Error", f"Connection failed: {e}")
        server.close()
        onion.close()
        tor.close()
        root.destroy()
        return

    root.mainloop()

# Client B: GUI
def client_b_main(onion_hostname, session_id, public_key_file):
    root = tk.Tk()
    root.title("Client B - Secure Chat")
    root.geometry("600x400")

    try:
        with open(public_key_file, "rb") as f:
            rsa_public_key_bytes = f.read()
        rsa_public_key = serialization.load_pem_public_key(rsa_public_key_bytes)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load public key: {e}")
        root.destroy()
        return

    ecdh_private_key, ecdh_public_key_bytes = x25519.X25519PrivateKey.generate(), \
                                              x25519.X25519PrivateKey.generate().public_key().public_bytes(
                                                  encoding=serialization.Raw,
                                                  format=serialization.PublicFormat.Raw
                                              )
    encrypted_key = rsa_public_key.encrypt(
        ecdh_public_key_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    try:
        tor = TorClient()
        conn = tor.connect(onion_hostname, 80)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to connect to Tor service: {e}")
        root.destroy()
        return

    conn.send(session_id.encode())
    conn.send(encrypted_key)

    ecdh_peer_public_key_bytes = conn.recv(32)
    try:
        session_key = derive_session_key(ecdh_private_key, ecdh_peer_public_key_bytes)
    except Exception as e:
        messagebox.showerror("Error", f"Session key derivation failed: {e}")
        conn.close()
        tor.close()
        root.destroy()
        return

    chat_display = tk.Text(root, height=15, width=60, state='disabled')
    chat_display.pack(pady=10)
    message_entry = tk.Entry(root, width=50)
    message_entry.pack(pady=5)

    def receive_messages():
        receiving_file = False
        file_buffer = b''
        file_name = ''
        file_size = 0
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                try:
                    rsa_public_key.verify(
                        data,
                        b"TERMINATE",
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
                    )
                    messagebox.showinfo("Info", "Session terminated by Client A")
                    conn.close()
                    tor.close()
                    root.destroy()
                    return
                except Exception:
                    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
                    if receiving_file:
                        try:
                            chunk = decrypt_bytes(nonce, ciphertext, tag, session_key)
                            file_buffer += chunk
                            if len(file_buffer) >= file_size:
                                save_path = filedialog.asksaveasfilename(initialfile=file_name)
                                if save_path:
                                    with open(save_path, 'wb') as f:
                                        f.write(file_buffer[:file_size])
                                chat_display.config(state='normal')
                                chat_display.insert(tk.END, f"Received file: {file_name}\n")
                                chat_display.config(state='disabled')
                                chat_display.see(tk.END)
                                receiving_file = False
                                file_buffer = b''
                                file_name = ''
                                file_size = 0
                            continue
                        except Exception as e:
                            messagebox.showerror("Error", f"File transfer failed: {e}")
                            receiving_file = False
                            file_buffer = b''
                            file_name = ''
                            file_size = 0
                            continue
                    try:
                        message = decrypt_message(nonce, ciphertext, tag, session_key)
                        if message.startswith("FILE_TRANSFER_START:"):
                            try:
                                _, fname, fsize = message.split(":", 2)
                                file_name = os.path.basename(fname)
                                file_size = int(fsize)
                                file_buffer = b''
                                receiving_file = True
                            except Exception as e:
                                messagebox.showerror("Error", f"Invalid file header: {e}")
                            continue
                        elif message == "FILE_TRANSFER_END":
                            receiving_file = False
                            file_buffer = b''
                            file_name = ''
                            file_size = 0
                            continue
                        chat_display.config(state='normal')
                        chat_display.insert(tk.END, f"Client A: {message}\n")
                        chat_display.config(state='disabled')
                        chat_display.see(tk.END)
                    except Exception as e:
                        messagebox.showerror("Error", f"Decryption failed: {e}")
            except Exception:
                break
        conn.close()
        tor.close()
        root.destroy()

    def send_message():
        message = message_entry.get()
        if not message:
            return
        try:
            nonce, ciphertext, tag = encrypt_message(message, session_key)
            conn.send(nonce + tag + ciphertext)
            chat_display.config(state='normal')
            chat_display.insert(tk.END, f"You: {message}\n")
            chat_display.config(state='disabled')
            chat_display.see(tk.END)
            message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Sending message failed: {e}")

    def send_file():
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            filename = os.path.basename(file_path)
            header = f"FILE_TRANSFER_START:{filename}:{len(data)}"
            nonce, ciphertext, tag = encrypt_message(header, session_key)
            conn.send(nonce + tag + ciphertext)
            chunk_size = 2048
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                n, c, t = encrypt_bytes(chunk, session_key)
                conn.send(n + t + c)
            nonce, ciphertext, tag = encrypt_message("FILE_TRANSFER_END", session_key)
            conn.send(nonce + tag + ciphertext)
            chat_display.config(state='normal')
            chat_display.insert(tk.END, f"Sent file: {filename}\n")
            chat_display.config(state='disabled')
            chat_display.see(tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"File transfer failed: {e}")

    tk.Button(root, text="Send", command=send_message).pack(pady=5)
    tk.Button(root, text="Send File", command=send_file).pack(pady=5)
    threading.Thread(target=receive_messages, daemon=True).start()
    root.mainloop()

# Client B Setup GUI
def client_b_setup():
    root = tk.Tk()
    root.title("Client B Setup")
    root.geometry("400x300")

    tk.Label(root, text="Onion Address:").pack(pady=5)
    onion_entry = tk.Entry(root, width=50)
    onion_entry.insert(0, sys.argv[2] if len(sys.argv) > 2 else "")
    onion_entry.pack(pady=5)

    tk.Label(root, text="Session ID:").pack(pady=5)
    session_entry = tk.Entry(root, width=50)
    session_entry.insert(0, sys.argv[3] if len(sys.argv) > 3 else "")
    session_entry.pack(pady=5)

    tk.Label(root, text="Public Key File:").pack(pady=5)
    key_entry = tk.Entry(root, width=50)
    key_entry.insert(0, sys.argv[4] if len(sys.argv) > 4 else "")
    key_entry.pack(pady=5)
    tk.Button(root, text="Browse", command=lambda: key_entry.insert(0, filedialog.askopenfilename())).pack(pady=5)

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
            messagebox.showerror("Error", "Failed to scan QR code")

    tk.Button(root, text="Scan QR Code", command=scan_and_fill).pack(pady=5)

    def start_client_b():
        onion_hostname = onion_entry.get()
        session_id = session_entry.get()
        public_key_file = key_entry.get()
        if not (onion_hostname and session_id and public_key_file):
            messagebox.showerror("Error", "All fields are required")
            return
        root.destroy()
        client_b_main(onion_hostname, session_id, public_key_file)

    tk.Button(root, text="Connect", command=start_client_b).pack(pady=10)
    root.mainloop()

# Main execution
if __name__ == "__main__":
    if args.mode == "client_a":
        client_a_main()
    else:
        client_b_setup()
