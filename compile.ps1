# PowerShell script to build OnionChat executables on Windows
# Ensure execution stops on errors
$ErrorActionPreference = 'Stop'

# Switch to the directory containing this script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir

# Install required Python packages and PyInstaller
pip install -r requirements.txt pyinstaller

# Build optional C extension
python setup.py build_ext --inplace

# Build Client A and Client B executables
python -m PyInstaller --onefile --windowed onionchat/client_a_main.py -n client_a_main
python -m PyInstaller --onefile --windowed onionchat/client_b_main.py -n client_b_main

Write-Host "Executables are available in the dist/ directory."
