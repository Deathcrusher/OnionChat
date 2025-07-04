# OnionChat 🧅💬

OnionChat is a secure, anonymous, one-time chat messenger built with Python. It leverages Tor hidden services for anonymity, RSA-4096 and ECDH (Curve25519) for key exchange with forward secrecy, AES-256-GCM for message encryption, and a user-friendly Tkinter GUI with QR code-based credential sharing. Designed for private, ephemeral communication, OnionChat ensures no persistent data is stored, with a kill switch controlled by Client A to prevent reconnection. 🔒🚀

## Features 🌟

- **End-to-End Encryption** 🔐: Messages are encrypted with AES-256-GCM, with keys exchanged via RSA-4096 and ECDH for forward secrecy.
- **Anonymity** 🕵️: Uses Tor hidden services via `torpy` (no external Tor installation required) to hide IP addresses.
- **One-Time Sessions** ⏳: Ephemeral sessions with no message storage and reconnection prevention.
- **Kill Switch** 🛑: Client A can terminate the session with a signed message, ensuring control.
- **QR Code Sharing** 📷: Encrypted QR codes (with passphrase) for secure sharing of onion address, session ID, and public key.
- **GUI Interface** 🖥️: Tkinter-based GUI for intuitive chat and setup, with integrated QR code scanning and display.
- **Message Padding** 📏: Fixed-length messages to prevent metadata leakage.
- **Secure File Transfer** 📁: Transfer files over the encrypted session.
- **Session Timeout** ⏰: Automatic termination after configurable inactivity period.
- **Cross-Platform** 🌐: Runs on Linux, Windows, and macOS with a graphical environment.

## Installation 🛠️

### Prerequisites ✅
- Python 3.10 or higher
- A graphical environment (e.g., X11 on Linux, Windows GUI, macOS)
- Internet connection for Tor network access
- Optional: Webcam for QR code scanning 📸

### Install Dependencies 📦
Run the following command to install required Python packages:
```bash
pip install -r requirements.txt
```

Alternatively, the script (`main.py`) automatically installs missing dependencies on first run.

### Clone the Repository 📥
```bash
git clone https://github.com/<your-username>/OnionChat.git
cd OnionChat
```


The codebase is organized into multiple modules: `client_a.py`, `client_b.py`, and `chat_utils.py` provide the core functionality while `main.py` remains the entry point.
## Usage 🎮

### Running Client A 🎤
Client A hosts the chat session and generates credentials (onion address, session ID, public key, and QR code).

```bash
python main.py client_a [--port PORT] [--timeout SECONDS] [--padding BYTES]
```

- **Options** ⚙️:
  - `--port`: Port for the Tor hidden service (default: 12345).
  - `--timeout`: Session inactivity timeout in seconds (default: 600).
  - `--padding`: Message padding length in bytes (default: 1024).
- **Output**: A GUI window displays the onion address, session ID, public key file (`client_a_public_key.pem`), and QR code. Enter a passphrase to encrypt the QR code data. Click "Copy QR Data" to copy the encrypted credentials to the clipboard. 📋
- **Share**: Share the QR code (displayed in GUI) or clipboard data with Client B via a secure channel (e.g., in-person scan, encrypted messaging). 🔐

### Running Client B 🎧
Client B connects to Client A’s session using the shared credentials.

```bash
python main.py client_b [<onion_hostname> <session_id> <public_key_file>] [--port PORT] [--timeout SECONDS] [--padding BYTES]
```

- **Options**: Same as Client A.
- **With Arguments**: If provided, the chat GUI opens directly.
- **Without Arguments**: A setup GUI opens, allowing manual entry, file browsing, or QR code scanning (via webcam or image file). Enter the passphrase to decrypt the QR code.
- **Click "Connect"** to join the chat. 🔗

### Chatting 💬
- **Send Messages**: Type in the input field and click "Send" (or press Enter).
- **Send Files**: Click "Send File" to securely transfer a selected file.
- **Client A Termination**: Click "Exit" or wait for the timeout to end the session, sending a signed termination message. 🛑
- **Client B**: GUI closes upon termination, preventing reconnection.

## Compiling for All Platforms 🖥️📱💻

OnionChat can be compiled into standalone executables for Linux, Windows, and macOS using PyInstaller, creating a single binary (~60-80 MB) that includes all dependencies.

### Prerequisites ✅
- Install PyInstaller:
  ```bash
  pip install pyinstaller
  ```
- Ensure a graphical environment is available on the target platform.

### Compilation Steps 🛠️
1. **Clone the Repository** (if not already done):
   ```bash
   git clone https://github.com/<your-username>/OnionChat.git
   cd OnionChat
```

   ```
2. **Compile the Binary**:
   - Run the following command in the repository directory:
     ```bash
     pyinstaller --onefile main.py
     ```
   - The binary will be created in the `dist/` directory (e.g., `dist/main` on Linux/macOS, `dist/main.exe` on Windows).
3. **Platform-Specific Notes**:
   - **Linux** 🐧:
     - Requires `python3-tk` for Tkinter (e.g., `sudo apt install python3-tk` on Debian/Ubuntu).
     - Ensure X11 or another graphical environment is running.
     - Test the binary: `./dist/main client_a`.
   - **Windows** 🪟:
     - Tkinter is included with Python; no additional setup needed.
     - Run the binary: `dist\main.exe client_a`.
     - If compiling on another platform for Windows, use Wine or a Windows VM, or specify `--target-architecture x64`.
   - **macOS** 🍎:
     - Tkinter is included with Python; ensure a Python version from python.org or Homebrew for best compatibility.
     - Run the binary: `./dist/main client_a`.
     - macOS may require signing the binary for Gatekeeper: `codesign -f -s - dist/main`.
4. **Distribute the Binary** 📤:
   - Copy the binary (`dist/main` or `dist/main.exe`) to the target machine.
   - Ensure the target machine has a graphical environment and internet access for Tor connectivity.
   - No Python or dependencies need to be installed on the target machine.

### Troubleshooting Compilation ⚠️
- **Large Binary Size**: The binary includes Python, Tkinter, `torpy`, `cryptography`, and other dependencies, resulting in ~60-80 MB. Use `--strip` to reduce size slightly, but expect large binaries due to OpenCV and Pillow.
- **Missing Dependencies**: If compilation fails, ensure all dependencies are installed (`pip install -r requirements.txt`).
- **Graphical Environment**: The binary requires a GUI environment; it will fail on headless servers.
- **Cross-Compilation**: For cross-platform builds, use a VM or Docker with the target OS, or tools like `pyinstaller --target-architecture` (limited support).

## Example Workflow 🚀
1. **Client A**:
   - Run: `python main.py client_a` or `./dist/main client_a`
   - GUI shows credentials and QR code. Enter a passphrase (e.g., "mysecret123"). 🔐
   - Copy clipboard data or display QR code for Client B.
2. **Client B**:
   - Run: `python main.py client_b` or `./dist/main client_b`
   - In the setup GUI, click "Scan QR Code" (use webcam or select image) or enter credentials manually. 📷
   - Enter the passphrase ("mysecret123").
   - Click "Connect" to start chatting.
3. **Chat**: Exchange messages securely. 💬
4. **End Session**: Client A clicks "Exit" or waits for timeout. Session terminates, and credentials are invalidated. 🛑

## Security Features 🔒
- **Cryptography**: RSA-4096 and ECDH (Curve25519) for key exchange, AES-256-GCM for message encryption with forward secrecy.
- **Anonymity**: Tor hidden services hide IP addresses, with ephemeral `.onion` addresses. 🕵️
- **QR Code Security**: Credentials encrypted with AES-256-GCM using a passphrase, displayed in-memory to avoid disk storage. 📷
- **Ephemerality**: No message or key storage, ensuring no forensic recovery. ⏳
- **Timeout and Kill Switch**: Prevents prolonged exposure and unauthorized reconnection. ⏰🛑

## Limitations ⚠️
- Requires a graphical environment for the GUI and QR code display.
- QR code scanning needs a webcam or image file. 📸
- Passphrase for QR code encryption must be shared securely out-of-band.
- `torpy` is less vetted than the official Tor client; monitor for updates.
- Compiled binary size is ~60-80 MB due to dependencies.

## Contributing 🤝
Contributions are welcome! Please follow these steps:
1. Fork the repository. 🍴
2. Create a branch: `git checkout -b feature-name`.
3. Commit changes: `git commit -m "Add feature-name"`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request. 📬

### Development Setup 🛠️
- Install dependencies: `pip install -r requirements.txt`.
- Test changes on Linux, Windows, or macOS with a graphical environment.
- Ensure Tor network connectivity for testing.

## License 📜
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact 📧
For issues or suggestions, open a GitHub issue or contact the maintainer at `<your-email>`.
