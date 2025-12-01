#!/bin/bash
# GCE startup script for Cloud-Based IDS
# Runs FastAPI (api.main:app) on port 8080 inside a virtualenv.

set -euo pipefail

LOG_FILE="/var/log/ids_startup.log"
exec >> "$LOG_FILE" 2>&1

echo "===== [$(date)] Starting IDS GCE startup script ====="

# Update and install dependencies
apt-get update -y
apt-get install -y python3 python3-venv python3-pip git

# Create app directory
APP_DIR="/opt/cloud-based-ids"
if [ ! -d "$APP_DIR" ]; then
  mkdir -p "$APP_DIR"
fi

cd "$APP_DIR"

# Clone or pull latest code
if [ ! -d ".git" ]; then
  echo "Cloning application repository..."
  git clone https://github.com/George-Muniz/Cloud-Based-IDS .   # <-- REPLACE THIS
else
  echo "Repository already exists, pulling latest changes..."
  git pull --rebase
fi

# Create / activate virtualenv
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install --upgrade pip

# Install requirements from root requirements.txt
if [ -f "requirements.txt" ]; then
  pip install -r requirements.txt
else
  echo "ERROR: requirements.txt not found in $APP_DIR"
fi

# Kill any old uvicorn processes, if they exist
pkill -f "uvicorn api.main:app" || true

# Start FastAPI app on port 8080
echo "Starting FastAPI (api.main:app) on port 8080..."
nohup python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8080 > /var/log/ids_app.log 2>&1 &

echo "===== [$(date)] IDS startup script completed ====="
