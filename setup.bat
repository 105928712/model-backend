@echo off
REM Create/activate the venv, install deps, then download and unzip the datasets. Usage: setup.bat
cd /d "%~dp0"

echo Setting up the development environment...
if not exist .venv\pyvenv.cfg python -m venv .venv
call .venv\Scripts\activate.bat
pip install -r requirements.txt