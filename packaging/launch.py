"""Lançador desktop do VaultDB Security Suite.

Inicia o Director API (FastAPI/uvicorn) localmente e abre o painel no navegador.
É o ponto de entrada empacotado pelo PyInstaller em VaultDB.exe (Windows) e VaultDB (macOS).

Sem Celery/Redis o backup corre em modo síncrono — adequado a uma instalação desktop.
Dados persistentes (backups/data/store.json) ficam em ./vaultdb-data junto ao executável
(ou em VAULTDB_HOME, se definido).
"""
import os
import sys
import threading
import time
import webbrowser

import uvicorn

# Garante que server.py é importável tanto em dev como empacotado.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import app  # noqa: E402


def _open_browser(url: str):
    time.sleep(1.8)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main():
    host = os.getenv("VAULTDB_HOST", "127.0.0.1")
    port = int(os.getenv("VAULTDB_PORT", "8000"))
    url = f"http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}"
    print("=" * 56)
    print("  VaultDB Security Suite — painel a iniciar")
    print(f"  Abra: {url}")
    print("  (feche esta janela para parar o servidor)")
    print("=" * 56)
    if os.getenv("VAULTDB_NO_BROWSER", "").lower() not in ("1", "true", "yes"):
        threading.Thread(target=_open_browser, args=(url,), daemon=True).start()
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
