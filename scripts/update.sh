#!/bin/bash
# Update script for ISSEC Toolset

echo "=== ISSEC Toolset Updater ==="
echo "[+] Pulling latest changes from git..."
git pull

echo "[+] Updating dependencies..."
# Use the python in .venv if it exists, otherwise assume python3
if [ -f ".venv/bin/python" ]; then
    .venv/bin/python -m pip install -r requirements.txt
    PYTHON=.venv/bin/python
else
    pip install -r requirements.txt
    PYTHON=python3
fi

echo "[+] Running post-deploy migrations..."
$PYTHON scripts/post_deploy.py

echo "=== Update Complete ==="
echo "Note: You may need to restart the service manually:"
echo "      e.g., sudo systemctl restart issec"
