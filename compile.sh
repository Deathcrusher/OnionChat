#!/usr/bin/env bash
# Build OnionChat executables.
set -e

# Ensure we're in the repo root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Install Python package requirements and PyInstaller
pip install -r requirements.txt pyinstaller

# Build optional C extension
python setup.py build_ext --inplace

# Build Client A and Client B executables
python -m PyInstaller --onefile --windowed -m onionchat.client_a_main -n client_a_main
python -m PyInstaller --onefile --windowed -m onionchat.client_b_main -n client_b_main

echo "Executables are available in the dist/ directory."
