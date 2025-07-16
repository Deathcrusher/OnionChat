use aes_gcm::aead::{Aead, KeyInit, Nonce};
use aes_gcm::{Aes256Gcm, Key};
use clap::{Parser, Subcommand};
use eframe::NativeOptions;
use std::process::{Child, Command};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use socks::Socks5Stream;
use tokio::runtime::Runtime;
use tokio_util::io::SyncIoBridge;
use arti_client::{TorClient, TorClientConfig};
mod gui;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use std::convert::TryInto;
type AesNonce = Nonce<Aes256Gcm>;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Launch the GUI interface
    #[arg(long)]
    gui: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Host a chat session
    Host {
        #[arg(long, default_value = "12345")]
        port: u16,
    },
    /// Connect to a hosted session
    Connect {
        host: String,
        #[arg(long, default_value = "12345")]
        port: u16,
    },
}

fn derive_key(secret: &[u8]) -> Key<Aes256Gcm> {
    let hk = Hkdf::<sha2::Sha256>::new(None, secret);
    let mut key_bytes = [0u8; 32];
    hk.expand(&[], &mut key_bytes).unwrap();
    (&key_bytes[..]).try_into().expect("HKDF output length")
}

fn start_tor_client() -> io::Result<Child> {
    let child = Command::new("tor")
        .arg("--quiet")
        .arg("--SocksPort").arg("9050")
        .spawn()?;
    thread::sleep(Duration::from_secs(5));
    Ok(child)
}

fn start_hidden_service(port: u16) -> io::Result<(TempDir, Child, String)> {
    let dir = tempfile::tempdir()?;
    let hs_dir = dir.path().join("hs");
    std::fs::create_dir_all(&hs_dir)?;
    let child = Command::new("tor")
        .arg("--quiet")
        .arg("--SocksPort").arg("9050")
        .arg(format!("--HiddenServiceDir {}", hs_dir.display()))
        .arg(format!("--HiddenServicePort {} 127.0.0.1:{}", port, port))
        .spawn()?;
    for _ in 0..30 {
        if let Ok(addr) = std::fs::read_to_string(hs_dir.join("hostname")) {
            return Ok((dir, child, addr.trim().to_string()));
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(io::Error::new(io::ErrorKind::Other, "tor start failed"))
}

fn send_packet<W: Write>(stream: &mut W, data: &[u8]) -> io::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(data)?;
    Ok(())
}

fn recv_packet<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn run_chat<S>(stream: S, cipher: Aes256Gcm, gui: bool, status: String) -> io::Result<()>
where
    S: Read + Write + Send + 'static,
{
    let stream = Arc::new(Mutex::new(stream));
    if gui {
        let (tx_gui, rx_net) = mpsc::channel::<String>();
        let (tx_net, rx_gui) = mpsc::channel::<String>();

        let reader_stream = Arc::clone(&stream);
        let cipher_recv = cipher.clone();
        thread::spawn(move || {
            loop {
                let mut s = reader_stream.lock().unwrap();
                match recv_packet(&mut *s) {
                    Ok(data) => {
                        if data.len() < 12 { continue; }
                        let nonce: AesNonce = data[..12].try_into().expect("nonce length");
                        let ct = &data[12..];
                        if let Ok(pt) = cipher_recv.decrypt(&nonce, ct) {
                            let _ = tx_gui.send(String::from_utf8_lossy(&pt).to_string());
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let writer_stream = Arc::clone(&stream);
        thread::spawn(move || {
            while let Ok(msg) = rx_gui.recv() {
                let mut nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce: AesNonce = nonce_bytes[..].try_into().unwrap();
                if let Ok(ct) = cipher.encrypt(&nonce, msg.as_bytes()) {
                    let mut payload = nonce_bytes.to_vec();
                    payload.extend_from_slice(&ct);
                    let mut s = writer_stream.lock().unwrap();
                    if send_packet(&mut *s, &payload).is_err() { break; }
                }
            }
        });

        let opts = NativeOptions::default();
        let _ = eframe::run_native(
            "OnionChat",
            opts,
            Box::new(move |cc| {
                Ok::<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>>(Box::new(gui::ChatApp::new(cc, tx_net, rx_net, status.clone())))
            }),
        );
        Ok(())
    } else {
        let reader_stream = Arc::clone(&stream);
        let cipher_recv = cipher.clone();
        thread::spawn(move || {
            loop {
                let mut s = reader_stream.lock().unwrap();
                match recv_packet(&mut *s) {
                    Ok(data) => {
                        if data.len() < 12 { continue; }
                        let nonce: AesNonce = data[..12].try_into().expect("nonce length");
                        let ct = &data[12..];
                        if let Ok(pt) = cipher_recv.decrypt(&nonce, ct) {
                            println!("< {}", String::from_utf8_lossy(&pt));
                        }
                    }
                    Err(e) => {
                        eprintln!("Receive error: {}", e);
                        break;
                    }
                }
            }
        });

        let stdin = io::stdin();
        loop {
            let mut input = String::new();
            stdin.read_line(&mut input)?;
            let input = input.trim_end();
            if input.is_empty() { continue; }
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce: AesNonce = nonce_bytes[..].try_into().unwrap();
            let ct = cipher.encrypt(&nonce, input.as_bytes()).unwrap();
            let mut payload = nonce_bytes.to_vec();
            payload.extend_from_slice(&ct);
            let mut s = stream.lock().unwrap();
            send_packet(&mut *s, &payload)?;
        }
    }
}

fn host(port: u16, gui: bool) -> io::Result<()> {
    let (_tmp, mut tor, onion) = start_hidden_service(port)?;
    println!("Onion address: {}", onion);
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("Waiting for connection on port {}...", port);
    let (mut stream, addr) = listener.accept()?;
    println!("Client connected from {}", addr);

    let secret = EphemeralSecret::random_from_rng(OsRng);
    let pubkey = X25519PublicKey::from(&secret);
    stream.write_all(pubkey.as_bytes())?;
    let mut peer_pub = [0u8; 32];
    stream.read_exact(&mut peer_pub)?;
    let peer_pub = X25519PublicKey::from(peer_pub);
    let shared = secret.diffie_hellman(&peer_pub);

    let key = derive_key(shared.as_bytes());
    let cipher = Aes256Gcm::new(&key);
    let status = format!("Hosting at {}", onion);
    let res = run_chat(stream, cipher, gui, status);
    let _ = tor.kill();
    res
}

fn connect(host: &str, port: u16, gui: bool) -> io::Result<()> {
    let mut tor = None;
    let mut stream: Box<dyn ReadWrite + Send> = if host.ends_with(".onion") {
        match start_tor_client() {
            Ok(child) => {
                tor = Some(child);
                Box::new(Socks5Stream::connect("127.0.0.1:9050", (host, port))?.into_inner())
            }
            Err(_) => {
                let rt = Runtime::new()?;
                let data = rt.block_on(async {
                    let cfg = TorClientConfig::default();
                    let client = TorClient::create_bootstrapped(cfg).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    let stream = client.connect((host, port)).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    Ok::<_, io::Error>(SyncIoBridge::new(stream))
                })?;
                Box::new(data)
            }
        }
    } else {
        Box::new(TcpStream::connect((host, port))?)
    };
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let pubkey = X25519PublicKey::from(&secret);
    let mut peer_pub = [0u8; 32];
    (&mut *stream).read_exact(&mut peer_pub)?;
    (&mut *stream).write_all(pubkey.as_bytes())?;
    let peer_pub = X25519PublicKey::from(peer_pub);
    let shared = secret.diffie_hellman(&peer_pub);

    let key = derive_key(shared.as_bytes());
    let cipher = Aes256Gcm::new(&key);
    let status = format!("Connected to {}", host);
    let res = run_chat(stream, cipher, gui, status);
    if let Some(mut t) = tor { let _ = t.kill(); }
    res
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Host { port } => host(port, cli.gui),
        Commands::Connect { host, port } => connect(&host, port, cli.gui),
    }
}
