import os
import sys
import importlib
import types
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from onionchat.main import check_dependencies, REQUIRED_PKGS


def test_check_dependencies_success():
    # Should not raise when dependencies are installed
    check_dependencies()


def test_check_dependencies_failure(monkeypatch):
    original_import = importlib.import_module

    def fake_import(name, package=None):
        if name == REQUIRED_PKGS[0].split("-")[0]:
            raise ImportError("missing")
        return original_import(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    with pytest.raises(RuntimeError):
        check_dependencies()
