#!/usr/bin/env bash
# Build do executável Linux (dist/VaultDB) — correr a partir da RAIZ do repositório:
#   bash packaging/build_linux.sh
set -euo pipefail

python3 -m venv .build-venv
# shellcheck disable=SC1091
source .build-venv/bin/activate
python -m pip install --upgrade pip
pip install -r packaging/requirements-desktop.txt

pyinstaller --clean --noconfirm packaging/vaultdb.spec

echo ""
echo "OK -> dist/VaultDB"
echo "Execute:  ./dist/VaultDB   (o painel abre em http://127.0.0.1:8000)"
