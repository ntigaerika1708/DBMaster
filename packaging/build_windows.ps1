# Build do executável Windows (VaultDB.exe) — correr a partir da RAIZ do repositório:
#   powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
$ErrorActionPreference = "Stop"

python -m venv .build-venv
.\.build-venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r packaging\requirements-desktop.txt

pyinstaller --clean --noconfirm packaging\vaultdb.spec

Write-Host ""
Write-Host "OK -> dist\VaultDB.exe" -ForegroundColor Green
Write-Host "Execute o .exe; o painel abre em http://127.0.0.1:8000"
