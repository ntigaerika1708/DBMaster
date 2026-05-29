# PyInstaller spec — VaultDB Security Suite (desktop, one-file)
# Build (a partir da RAIZ do repositório):
#   pyinstaller --clean --noconfirm packaging/vaultdb.spec
#
# Gera dist/VaultDB (macOS/Linux) ou dist/VaultDB.exe (Windows).
import os
from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.getcwd())

hiddenimports = (
    collect_submodules("uvicorn")
    + collect_submodules("starlette")
    + collect_submodules("anyio")
    + [
        "jose.backends.cryptography_backend",
        "passlib.handlers.bcrypt",
        "pymysql",
        "psycopg2",
        "httpx",
        "prometheus_client",
        "email.mime.text",
        "email.mime.multipart",
    ]
)

# Recursos empacotados: o painel SPA.
datas = [(os.path.join(ROOT, "index.html"), ".")]

# Mantém o binário enxuto: features opcionais carregam por import tardio (e devolvem 501 se ausentes).
excludes = ["pyarrow", "pandas", "numpy", "boto3", "botocore", "celery", "kombu", "pyodbc", "tkinter"]

a = Analysis(
    [os.path.join(ROOT, "packaging", "launch.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="VaultDB",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# Em macOS, gera também dist/VaultDB.app (ignorado nas outras plataformas).
app = BUNDLE(
    exe,
    name="VaultDB.app",
    icon=None,
    bundle_identifier="com.vaultdb.suite",
    info_plist={
        "CFBundleName": "VaultDB",
        "CFBundleDisplayName": "VaultDB Security Suite",
        "CFBundleShortVersionString": os.getenv("VAULTDB_VERSION", "2.2.1"),
        "LSBackgroundOnly": False,
    },
)
