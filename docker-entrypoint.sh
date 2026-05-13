#!/bin/bash
set -e

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║           ACMD TOOLBOX — Démarrage                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Outils disponibles
echo "[*] Outils pré-installés :"
for tool in nmap nikto gobuster dirb sqlmap hydra wfuzz curl wget; do
    if command -v "$tool" &>/dev/null; then
        echo "    ✓ $tool ($(which $tool))"
    else
        echo "    ✗ $tool (absent)"
    fi
done
echo ""

# Base de données
echo "[*] Base de données : ${DB_PATH:-/app/toolbox.db}"
echo "[*] Démarrage Flask sur http://0.0.0.0:5000"
echo ""

# Lancer Flask (Gunicorn en prod, Flask dev sinon)
if command -v gunicorn &>/dev/null; then
    exec gunicorn \
        --bind 0.0.0.0:5000 \
        --workers 2 \
        --threads 4 \
        --timeout 120 \
        --access-logfile - \
        --error-logfile - \
        app:app
else
    exec python3 app.py
fi
