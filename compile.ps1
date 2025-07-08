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
pyinstaller --onefile --windowed -m onionchat.client_a_main -n client_a_main
pyinstaller --onefile --windowed -m onionchat.client_b_main -n client_b_main

Write-Host "Executables are available in the dist/ directory."
