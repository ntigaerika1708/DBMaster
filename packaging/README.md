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

- `VaultDB.exe` (Windows x64) e `VaultDB-macos-*` (macOS arm64/x64)
- binários do **agente Go** para Linux/macOS/Windows (amd64/arm64)
