import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from onionchat.chat_utils import encrypt_message, decrypt_message, secure_wipe


def test_encrypt_message_too_long():
    key = b"0" * 32
    with pytest.raises(ValueError):
        encrypt_message("a" * 2000, key, 32)


def test_secure_wipe():
    data = bytearray(b"secret")
    secure_wipe(data)
    assert all(b == 0 for b in data)


def test_cli_parsing():
    from onionchat import client_a_main
    args = client_a_main.parse_args([])
    assert args.port == 12345


def test_client_b_default_args():
    from onionchat import client_b_main
    args = client_b_main.parse_args([])
    assert args.padding == 1024
    assert args.max_file_size == 100
    assert args.tor_impl == "stem"
    assert args.onion is None
    assert args.session is None
    assert args.key is None


def test_download_tor_bundle(monkeypatch, tmp_path):
    import tarfile
    import shutil
    import urllib.request
    import platform
    from onionchat.chat_utils import _download_tor_bundle

    tarball = tmp_path / "tor-expert-bundle-linux-x86_64-14.5.4.tar.gz"
    tor_inner = tmp_path / "tor_inner" / "tor"
    tor_inner.mkdir(parents=True)
    (tor_inner / "tor").write_text("dummy")
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(tor_inner, arcname="tor")

    def fake_retrieve(url, dest):
        shutil.copy(tarball, dest)

    monkeypatch.setattr(urllib.request, "urlretrieve", fake_retrieve)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(os, "chmod", lambda *a, **k: None)

    dest = _download_tor_bundle(str(tmp_path))
    assert dest and dest.endswith("tor")
    assert os.path.exists(dest)

