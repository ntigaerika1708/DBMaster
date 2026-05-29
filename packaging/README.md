# Empacotamento desktop — VaultDB (Windows .exe / macOS)

Gera um **executável único** que arranca o Director API (FastAPI) e abre o painel no navegador.
Ideal para uma instalação local sem Docker. Backups corre em **modo síncrono** (sem Celery/Redis).

## Conteúdo

| Ficheiro | Função |
|---|---|
| `launch.py` | Ponto de entrada: inicia uvicorn e abre `http://127.0.0.1:8000` |
| `vaultdb.spec` | Receita PyInstaller (one-file, inclui `index.html`) |
| `requirements-desktop.txt` | Dependências mínimas do build |
| `build_windows.ps1` | Build local no Windows → `dist/VaultDB.exe` |
| `build_macos.sh` | Build local no macOS → `dist/VaultDB` |

## Build local

**Windows** (PowerShell, a partir da raiz do repo):

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
```

**macOS** (a partir da raiz do repo):

```bash
bash packaging/build_macos.sh
```

> Use a arquitetura do Python instalado: num Mac Apple Silicon o resultado é arm64; num Intel, x86_64.

## Execução

- Windows: duplo clique em `dist\VaultDB.exe` (ou execute na consola).
- macOS: `./dist/VaultDB`.

O painel abre automaticamente. Dados persistentes (backups, `store.json`) ficam em
`vaultdb-data/` junto ao executável, ou no caminho definido por `VAULTDB_HOME`.

Variáveis úteis: `VAULTDB_HOST` (default `127.0.0.1`), `VAULTDB_PORT` (default `8000`),
`VAULTDB_NO_BROWSER=1` (não abrir o navegador), `VAULTDB_HOME` (pasta de dados).

Login inicial: **admin / vaultdb2024** (altere em Configurações).

## Builds automáticos (CI)

Ao criar uma tag `v*` (ex.: `git tag v2.2.0 && git push origin v2.2.0`), o workflow
`.github/workflows/release.yml` compila e publica numa **GitHub Release**:

- `VaultDB.exe` (Windows x64) + **instalador MSI** `VaultDB-<versão>-x64.msi` (WiX)
- `VaultDB_<versão>_macos_*.dmg` (+ `.tar.gz`) para arm64/x64
- `VaultDB-<versão>-x86_64.AppImage` (Linux) + `VaultDB_<versão>_linux_x64.tar.gz`
- binários do **agente Go** para Linux/macOS/Windows (amd64/arm64)

### Build local dos instaladores

```powershell
# Windows MSI (após dist\VaultDB.exe), a partir da raiz:
dotnet tool install --global wix
wix build packaging\windows_installer.wxs -d Version=2.2.3 -o out\VaultDB-2.2.3-x64.msi
```

```bash
# Linux AppImage (após dist/VaultDB), a partir da raiz:
mkdir -p VaultDB.AppDir/usr/bin
cp dist/VaultDB VaultDB.AppDir/usr/bin/VaultDB
cp packaging/appimage/AppRun VaultDB.AppDir/ && chmod +x VaultDB.AppDir/AppRun
cp packaging/appimage/VaultDB.desktop packaging/appimage/vaultdb.svg VaultDB.AppDir/
wget https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage -O appimagetool && chmod +x appimagetool
ARCH=x86_64 ./appimagetool VaultDB.AppDir out/VaultDB-x86_64.AppImage
```

## Assinatura de código (opcional)

Os binários funcionam sem assinatura, mas o Windows (SmartScreen) e o macOS (Gatekeeper)
mostram avisos de "editor não verificado". Para assinar/notarizar automaticamente no CI,
adicione estes **GitHub Secrets** (Settings → Secrets and variables → Actions). Sem eles,
os passos de assinatura são saltados.

**Windows (Authenticode):**

| Secret | Conteúdo |
|---|---|
| `WINDOWS_PFX_BASE64` | certificado `.pfx` em base64 (`base64 -w0 cert.pfx`) |
| `WINDOWS_PFX_PASSWORD` | palavra-passe do `.pfx` |

**macOS (Developer ID + notarização):**

| Secret | Conteúdo |
|---|---|
| `MACOS_CERT_P12` | certificado "Developer ID Application" `.p12` em base64 |
| `MACOS_CERT_PASSWORD` | palavra-passe do `.p12` |
| `MACOS_SIGN_IDENTITY` | ex.: `Developer ID Application: A Sua Empresa (TEAMID)` |
| `APPLE_ID` | Apple ID para notarização |
| `APPLE_TEAM_ID` | Team ID (10 caracteres) |
| `APPLE_APP_PASSWORD` | app-specific password do Apple ID |

> Estes certificados são pagos/emitidos pela Apple/CA — só você os pode fornecer.
> O workflow já está preparado: ao definir os secrets, a próxima tag `v*` gera artefactos assinados.
