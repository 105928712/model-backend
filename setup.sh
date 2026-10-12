#!/usr/bin/env bash
# Create/activate the venv, install deps, then download and unzip the datasets. Usage: source setup.sh
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "Setting up the development environment..."
[ -f .venv/pyvenv.cfg ] || python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt