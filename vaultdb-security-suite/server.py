#!/usr/bin/env python3
"""
VaultDB Security Suite — Director API v2.0
Plataforma enterprise de Backup & Disaster Recovery para MySQL/MariaDB
PO: Natã (Coordenação de Infraestrutura)

Endpoints:
  POST /api/auth/token                  → JWT login
  POST /api/connections                 → cadastrar conexão
  GET  /api/connections                 → listar conexões
  POST /api/connections/test            → testar conexão
  GET  /api/connections/{id}/tables     → listar tabelas (com ER hints)
  POST /api/backups/trigger             → disparar backup (task Celery)
  GET  /api/backups/{file}/meta          → metadados do backup (versão MySQL, etc.)
  POST /api/linux-prepare/script          → gera script bash para preparar Linux (módulo DR)
  GET  /api/backups/{id}/status         → status da task
  POST /api/restore/request             → solicitar restore (cria pendência)
  GET  /api/restore/confirm?token=...   → página HTML (abrir link no browser — sem 405)
  POST /api/restore/approve-submit      → POST formulário (corpo: token)
  POST /api/restore/approve/{token}     → aprovar (JSON painel)
  GET  /api/settings                    → SMTP/Telegram (admin)
  PUT  /api/settings                    → gravar SMTP/Telegram (admin)
  POST /api/settings/test-smtp          → testar e-mail (admin)
  GET  /api/users                       → listar utilizadores (admin)
  POST /api/users                       → criar utilizador (admin)
  DELETE /api/users/{username}          → remover (admin)
  POST /api/users/{username}/password   → alterar palavra-passe (admin)
  GET  /api/schedules                   → listar agendamentos
  POST /api/schedules                   → criar agendamento GFS/CRON
  GET  /api/audit                       → trilha de auditoria
  GET  /metrics                         → Prometheus metrics
  GET  /api/er-diagram/{conn_id}/{db}   → diagrama ER (chaves estrangeiras)
  POST /api/export/parquet              → exportar para Parquet / S3
  POST /api/alerts/test                 → testar alertas Telegram
"""

import base64
import hashlib
import html
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
from urllib.parse import quote
from datetime import datetime, timedelta
from typing import Optional

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from prometheus_client import Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, Field
from starlette.responses import Response

# ── Optional imports ──────────────────────────────────────────────────────────
try:
    from celery import Celery
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False

try:
    from jose import JWTError, jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

log = structlog.get_logger()

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "vaultdb-dev-secret-CHANGE-IN-PROD")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
BACKUP_DIR = os.path.join(os.path.dirname(__file__), "backups")
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)


def _mysqldump_ssl_arg_variants() -> list:
    """
    Argumentos extras por tentativa (após --defaults-extra-file).
    MariaDB 11 não aceita --ssl-mode=DISABLED (só cliente Oracle MySQL 8+).
    Com ssl=0 no .cnf, a primeira tentativa costuma ser [].
    MYSQLDUMP_SSL_MODE=DEFAULT — sem flags extras nem opções TLS no .cnf (use MYSQLDUMP_EXTRA_ARGS se precisar).
    """
    raw = os.getenv("MYSQLDUMP_SSL_MODE", "DISABLED").strip().upper()
    if raw in ("DEFAULT", "SERVER", "AUTO"):
        return [[]]
    extra = os.getenv("MYSQLDUMP_EXTRA_ARGS", "").strip()
    if extra:
        return [shlex.split(extra)]
    if raw in ("DISABLED", "OFF", "FALSE", "0", "NO", "NO_SSL"):
        return [
            [],
            ["--skip-ssl"],
            ["--skip-ssl-verify-server-cert"],
            ["--ssl-mode=DISABLED"],
        ]
    if raw == "PREFERRED":
        return [["--ssl-mode=PREFERRED"]]
    if raw in ("REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY"):
        return [[f"--ssl-mode={raw}"]]
    return [[], ["--skip-ssl"], ["--ssl-mode=DISABLED"]]

# ── Persistence (JSON flat-file para dev; substituir por SQLAlchemy em prod) ──
STORE_FILE = os.path.join(DATA_DIR, "store.json")


def _default_store() -> dict:
    return {
        "connections": {},
        "schedules": {},
        "audit": [],
        "restore_requests": {},
        "users": {
            "admin": {
                "password_hash": hashlib.sha256(b"vaultdb2024").hexdigest(),
                "role": "admin",
            }
        },
        "settings": {
            "smtp_host": (os.getenv("SMTP_HOST") or "").strip(),
            "smtp_port": int(os.getenv("SMTP_PORT", "587") or 587),
            "smtp_user": (os.getenv("SMTP_USER") or "").strip(),
            "smtp_pass": (os.getenv("SMTP_PASS") or "").strip(),
            "telegram_token": (os.getenv("TELEGRAM_TOKEN") or "").strip(),
            "telegram_chat_id": (os.getenv("TELEGRAM_CHAT_ID") or "").strip(),
        },
    }


def _ensure_store_defaults(data: dict) -> bool:
    """Garante chaves obrigatórias; devolve True se alterou (para gravar)."""
    changed = False
    if not isinstance(data, dict):
        return False
    for key, default in _default_store().items():
        if key not in data:
            data[key] = json.loads(json.dumps(default))  # deep copy simples
            changed = True
    if "users" in data and isinstance(data["users"], dict):
        for uname, u in data["users"].items():
            if isinstance(u, dict) and "role" not in u:
                u["role"] = "admin" if uname == "admin" else "viewer"
                changed = True
    if "settings" in data and isinstance(data["settings"], dict):
        s = data["settings"]
        for k, v in _default_store()["settings"].items():
            if k not in s:
                s[k] = v
                changed = True
        if "smtp_port" in s and isinstance(s["smtp_port"], str):
            try:
                s["smtp_port"] = int(s["smtp_port"])
                changed = True
            except ValueError:
                s["smtp_port"] = 587
                changed = True
    return changed


def load_store() -> dict:
    if not os.path.exists(STORE_FILE):
        return _default_store()
    with open(STORE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    if _ensure_store_defaults(data):
        save_store(data)
    return data

def save_store(store: dict):
    with open(STORE_FILE, "w") as f:
        json.dump(store, f, indent=2, default=str)

STORE = load_store()

# ── Celery ────────────────────────────────────────────────────────────────────
if CELERY_AVAILABLE:
    celery_app = Celery("vaultdb", broker=REDIS_URL, backend=REDIS_URL)
    celery_app.conf.task_serializer = "json"
    celery_app.conf.result_serializer = "json"
    celery_app.conf.imports = ("tasks",)
    celery_app.conf.result_expires = 86400

# ── Prometheus metrics ────────────────────────────────────────────────────────
backup_total = Counter("vaultdb_backups_total", "Total backups", ["engine", "status"])
backup_size_bytes = Histogram("vaultdb_backup_size_bytes", "Backup sizes", buckets=[1e6, 10e6, 100e6, 1e9])
active_connections = Gauge("vaultdb_active_connections", "Registered DB connections")
restore_requests = Counter("vaultdb_restore_requests_total", "Restore requests", ["status"])

# ── FastAPI App ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="VaultDB Security Suite",
    version="2.0.0",
    description="Enterprise Backup & Disaster Recovery — Application-Aware",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)

# ── Models ────────────────────────────────────────────────────────────────────

class ConnectionConfig(BaseModel):
    name: str
    engine: str  # mysql | postgresql | mssql | mongodb
    host: str
    port: int
    user: str
    password: str
    database: Optional[str] = None
    tags: list[str] = []
    notes: Optional[str] = None

class BackupTrigger(BaseModel):
    connection_id: str
    database: str
    tables: Optional[list[str]] = None
    backup_type: str = "full"  # full | incremental | differential
    compression: str = "zstd"  # gzip | zstd | none
    throttle_mbps: Optional[int] = None
    output_name: Optional[str] = None
    export_parquet: bool = False
    s3_bucket: Optional[str] = None

class RestoreRequest(BaseModel):
    connection_id: str
    database: str
    backup_file: str
    tables: Optional[list[str]] = None
    requestor_email: str
    justification: str
    mask_lgpd: bool = False


class LinuxPrepareScriptRequest(BaseModel):
    """Gera script bash para preparar um Linux com MySQL/MariaDB alinhado ao backup."""
    connection_id: str
    backup_file: str
    target_database: str
    install_server: bool = True
    package_flavor: str = "auto"  # auto | mariadb | mysql


class ScheduleCreate(BaseModel):
    name: str
    connection_id: str
    database: str
    cron_expression: str  # ex: "0 2 * * *"
    backup_type: str = "full"  # full | incremental | gfs
    retention_days: int = 30
    compression: str = "zstd"
    throttle_mbps: Optional[int] = None
    notify_telegram: bool = True
    enabled: bool = True

class AlertTest(BaseModel):
    message: str = "VaultDB test alert 🔔"

class TokenRequest(BaseModel):
    username: str
    password: str


class SettingsUpdate(BaseModel):
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_pass: Optional[str] = None  # vazio = não alterar; "__CLEAR__" = limpar
    telegram_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None


class SmtpTestRequest(BaseModel):
    to: str


class UserCreate(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=4)
    role: str = "viewer"  # admin | viewer


class UserPasswordUpdate(BaseModel):
    password: str = Field(..., min_length=4)


# ── Auth ──────────────────────────────────────────────────────────────────────

def verify_password(plain: str, hashed: str) -> bool:
    return hashlib.sha256(plain.encode()).hexdigest() == hashed

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    if not JWT_AVAILABLE:
        return f"dev-token-{data.get('sub', 'user')}"
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)) -> Optional[dict]:
    if not token:
        return None
    if not JWT_AVAILABLE or token.startswith("dev-token-"):
        return {"sub": "admin", "role": "admin"}
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        store = load_store()
        user = store["users"].get(username)
        if not user:
            return None
        return {**user, "sub": username}
    except JWTError:
        return None

def require_auth(user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Não autenticado")
    return user


def require_admin(user=Depends(require_auth)):
    if user.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Apenas administradores")
    return user


# ── Audit ──────────────────────────────────────────────────────────────────────

def audit_log(action: str, user: str, resource: str, detail: str, risk: str = "low"):
    store = load_store()
    entry = {
        "id": secrets.token_hex(8),
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "user": user,
        "resource": resource,
        "detail": detail,
        "risk": risk,  # low | medium | high | critical
        "ip": "system"
    }
    store["audit"].append(entry)
    if len(store["audit"]) > 5000:
        store["audit"] = store["audit"][-5000:]
    save_store(store)
    log.info("audit", **entry)

# ── DB Helpers ─────────────────────────────────────────────────────────────────

def get_conn_by_id(conn_id: str) -> ConnectionConfig:
    store = load_store()
    data = store["connections"].get(conn_id)
    if not data:
        raise HTTPException(404, f"Conexão '{conn_id}' não encontrada")
    return ConnectionConfig(**data)

def connect_mysql(cfg: ConnectionConfig):
    import pymysql
    kwargs = dict(
        host=cfg.host, port=cfg.port,
        user=cfg.user, password=cfg.password,
        connect_timeout=8, charset="utf8mb4"
    )
    if cfg.database:
        kwargs["database"] = cfg.database
    return pymysql.connect(**kwargs)

def connect_pg(cfg: ConnectionConfig):
    import psycopg2
    return psycopg2.connect(
        host=cfg.host, port=cfg.port,
        user=cfg.user, password=cfg.password,
        dbname=cfg.database or "postgres", connect_timeout=8
    )

def connect_mongo(cfg: ConnectionConfig):
    from pymongo import MongoClient
    uri = f"mongodb://{cfg.user}:{cfg.password}@{cfg.host}:{cfg.port}/"
    client = MongoClient(uri, serverSelectionTimeoutMS=8000)
    client.server_info()
    return client


def _mysql_select_version(cfg: ConnectionConfig) -> str:
    c = connect_mysql(cfg)
    try:
        cur = c.cursor()
        cur.execute("SELECT VERSION()")
        return (cur.fetchone() or ("unknown",))[0]
    finally:
        c.close()


def _write_mysql_backup_meta(
    sql_path: str,
    conn: ConnectionConfig,
    database: str,
    backup_type: str,
    tables: Optional[list],
    method: str,
    mysql_version: str,
):
    meta = {
        "engine": "mysql",
        "database": database,
        "mysql_version": mysql_version,
        "backup_type": backup_type,
        "tables": tables,
        "method": method,
        "created": datetime.now().isoformat(),
    }
    try:
        with open(sql_path + ".meta.json", "w", encoding="utf-8") as mf:
            json.dump(meta, mf, indent=2, default=str)
    except OSError:
        pass


def _load_backup_meta(backup_file: str) -> dict:
    base = os.path.join(BACKUP_DIR, backup_file)
    meta_path = base + ".meta.json"
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _peek_mysql_dump_header(sql_path: str) -> dict:
    """Lê cabeçalho de .sql gerado por mysqldump (backups antigos sem .meta.json)."""
    meta: dict = {"engine": "mysql", "mysql_version": None, "database": None}
    try:
        with open(sql_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(80):
                line = f.readline()
                if not line:
                    break
                if "Server version" in line:
                    m = re.search(r"Server version[:\s]+(.+)", line, re.I)
                    if m:
                        meta["mysql_version"] = m.group(1).strip().strip("`")
                if re.match(r"^--\s*Host:", line):
                    m = re.search(r"Database:\s*(\S+)", line)
                    if m:
                        meta["database"] = m.group(1).strip()
    except OSError:
        pass
    return meta


def _package_flavor_from_version(version_hint: str, explicit: str) -> str:
    if explicit in ("mariadb", "mysql"):
        return explicit
    v = (version_hint or "").lower()
    if "mariadb" in v:
        return "mariadb"
    return "mysql"


def build_linux_mysql_prepare_script(
    *,
    mysql_version_hint: str,
    target_database: str,
    app_user: str,
    app_password: str,
    package_flavor: str,
    install_server: bool,
) -> str:
    """
    Script bash para Ubuntu/Debian (sudo): instala servidor, cria banco e utilizador
    com as mesmas credenciais da conexão VaultDB — restore passa a funcionar sem ajustes manuais.
    """
    flavor = _package_flavor_from_version(mysql_version_hint, package_flavor)
    pkg = "mariadb-server" if flavor == "mariadb" else "default-mysql-server"
    db_esc = target_database.replace("`", "").replace("\\", "")
    user_esc = app_user.replace("`", "").replace("\\", "").replace("'", "")
    pw_sql = app_password.replace("\\", "\\\\").replace("'", "''")

    install_block = (
        f"""
if [ "${{INSTALL_MYSQL:-1}}" = "1" ]; then
  echo "==> Instalando servidor ({pkg}) — versão exata do backup pode exigir repositório oficial Oracle/MariaDB."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}
  systemctl enable --now mysql 2>/dev/null || systemctl enable --now mariadb 2>/dev/null || true
  sleep 2
fi
"""
        if install_server
        else '\necho "==> Instalação do servidor desativada (install_server=false)"\n'
    )

    sql_setup = (
        f"CREATE DATABASE IF NOT EXISTS `{db_esc}`;\n"
        f"CREATE USER IF NOT EXISTS '{user_esc}'@'%' IDENTIFIED BY '{pw_sql}';\n"
        f"GRANT ALL PRIVILEGES ON `{db_esc}`.* TO '{user_esc}'@'%';\n"
        "FLUSH PRIVILEGES;\n"
    )
    b64_sql = base64.b64encode(sql_setup.encode("utf-8")).decode("ascii")

    return f"""#!/usr/bin/env bash
# Gerado pelo VaultDB — preparação Linux para restore MySQL/MariaDB
# Versão de referência (origem do backup): {mysql_version_hint or "desconhecida"}
# Pacote sugerido: {pkg}
# Executar no Linux de destino:
#   chmod +x vaultdb-prepare-restore.sh && sudo ./vaultdb-prepare-restore.sh
set -euo pipefail
export INSTALL_MYSQL={1 if install_server else 0}
{install_block}
echo "==> Criar banco, utilizador e permissões (sudo mysql)..."
echo "{b64_sql}" | base64 -d | sudo mysql
echo "==> Concluído. Utilizador: {user_esc} | Base: {db_esc}"
echo "==> No VaultDB: Restaurar → mesma conexão (host/porta deste Linux) e este banco."
"""


def _mysql_ensure_restore_privileges(db_conn, database: str, app_user: str, app_password: str):
    """Garante banco existente e utilizador da conexão com permissões de restore."""
    cur = db_conn.cursor()
    db = database.replace("`", "").replace("'", "")
    user = app_user.replace("`", "").replace("'", "")
    pw_sql = app_password.replace("\\", "\\\\").replace("'", "''")
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db}`")
    cur.execute(f"CREATE USER IF NOT EXISTS '{user}'@'%' IDENTIFIED BY '{pw_sql}'")
    try:
        cur.execute(f"ALTER USER '{user}'@'%' IDENTIFIED BY '{pw_sql}'")
    except Exception:
        pass
    cur.execute(f"GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'%'")
    try:
        cur.execute(f"GRANT SESSION_VARIABLES_ADMIN ON *.* TO '{user}'@'%'")
    except Exception:
        pass
    cur.execute("FLUSH PRIVILEGES")
    cur.execute(f"USE `{db}`")


# Statements de gestão de sessão que partem o fallback PyMySQL.
# Em dumps mysqldump/MariaDB o par abaixo guarda/repõe o autocommit numa variável de utilizador:
#   SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;  ...  SET AUTOCOMMIT=@OLD_AUTOCOMMIT;
# Quando a variável fica NULL (ex.: split por ';'), o MySQL 8 rejeita com erro 1231.
# Como gerimos o commit do nosso lado, ignoramos qualquer SET de AUTOCOMMIT e o par UNIQUE/FK checks fica intacto.
_RE_MYSQL_AUTOCOMMIT_SET = re.compile(r"(?is)^\s*SET\s+.*\bAUTOCOMMIT\b")
_RE_MYSQL_LOCK = re.compile(r"(?is)^\s*(UN)?LOCK\s+TABLES\b")
_RE_SANDBOX = re.compile(r"(?is)^/\*M?!\d*\\?-?\s*enable the sandbox mode\s*\*/\s*;?\s*$")


def _mysql_restore_stmt_should_skip(stmt: str) -> bool:
    s = stmt.strip()
    if not s or s.startswith("--"):
        return True
    if _RE_SANDBOX.match(s):
        return True
    if _RE_MYSQL_AUTOCOMMIT_SET.match(s):
        return True
    if _RE_MYSQL_LOCK.match(s):
        return True
    return False


def _mysql_client_binary() -> Optional[str]:
    """Em Debian, default-mysql-client instala `mariadb`; aceitamos ambos."""
    for cand in ("mysql", "mariadb"):
        if shutil.which(cand):
            return cand
    return None


def _run_mysql_restore_via_cli(cfg: ConnectionConfig, database: str, sql_path: str) -> Optional[dict]:
    """
    Restaura com o cliente de linha de comando (`mysql`/`mariadb`). O dump é aplicado como fluxo
    completo — lida nativamente com a linha de sandbox MariaDB, LOCK TABLES e o par AUTOCOMMIT,
    evitando o split frágil por ';' do fallback PyMySQL.
    """
    binary = _mysql_client_binary()
    if not binary:
        return None
    db = database.replace("`", "").replace("'", "")
    cnf = tempfile.NamedTemporaryFile(mode="w", suffix=".cnf", delete=False, encoding="utf-8")
    try:
        cnf.write("[client]\n")
        cnf.write(f"host={cfg.host}\nport={cfg.port}\nuser={cfg.user}\npassword={cfg.password}\n")
        # MariaDB 11 não aceita --ssl-mode; ssl=0 desliga TLS de forma compatível.
        cnf.write("ssl=0\n")
        cnf.close()
        with open(sql_path, "rb") as sqlf:
            proc = subprocess.run(
                [
                    binary,
                    f"--defaults-extra-file={cnf.name}",
                    "--default-character-set=utf8mb4",
                    "--force",  # continua apesar de erros não fatais (ex.: 1231 do autocommit)
                    db,
                ],
                stdin=sqlf,
                capture_output=True,
                timeout=7200,
            )
        out = (proc.stdout or b"").decode("utf-8", errors="replace")
        err = (proc.stderr or b"").decode("utf-8", errors="replace")
        # Ignora avisos benignos (autocommit NULL, sandbox) ao avaliar falha real.
        fatal = proc.returncode != 0 and not re.search(r"1231|sandbox", err, re.IGNORECASE)
        if fatal:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                f"Cliente {binary} falhou (código {proc.returncode}). Detalhe:\n{(err or out)[-6000:]}",
            )
        return {
            "database": database,
            "statements_executed": 0,
            "errors": [l for l in err.splitlines() if l.strip()][:5],
            "backup_file": os.path.basename(sql_path),
            "restore_mode": f"{binary}_cli",
            "message": f"Restore concluído via cliente {binary} (dump aplicado em streaming).",
        }
    finally:
        try:
            os.unlink(cnf.name)
        except OSError:
            pass


# ── Routes: Auth ───────────────────────────────────────────────────────────────

@app.post("/api/auth/token", tags=["Auth"])
def login(form: OAuth2PasswordRequestForm = Depends()):
    store = load_store()
    user = store["users"].get(form.username)
    if not user or not verify_password(form.password, user["password_hash"]):
        raise HTTPException(401, "Credenciais inválidas")
    token = create_access_token({"sub": form.username, "role": user.get("role", "viewer")})
    audit_log("LOGIN", form.username, "auth", "Login bem-sucedido")
    return {"access_token": token, "token_type": "bearer", "role": user.get("role", "viewer")}

@app.post("/api/auth/token/json", tags=["Auth"])
def login_json(body: TokenRequest):
    store = load_store()
    user = store["users"].get(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Credenciais inválidas")
    token = create_access_token({"sub": body.username, "role": user.get("role", "viewer")})
    audit_log("LOGIN", body.username, "auth", "Login JSON bem-sucedido")
    return {"access_token": token, "token_type": "bearer", "role": user.get("role", "viewer")}

# ── Routes: Connections ────────────────────────────────────────────────────────

@app.post("/api/connections", tags=["Connections"])
def create_connection(cfg: ConnectionConfig, user=Depends(require_auth)):
    store = load_store()
    conn_id = f"{cfg.engine}-{cfg.host}-{cfg.name}".replace(" ", "_").lower()
    conn_id = hashlib.md5(conn_id.encode()).hexdigest()[:12]
    store["connections"][conn_id] = {**cfg.dict(), "id": conn_id, "created": datetime.now().isoformat()}
    save_store(store)
    active_connections.set(len(store["connections"]))
    audit_log("CONN_CREATE", user["sub"] if isinstance(user, dict) else "admin", conn_id, f"Conexão {cfg.name} ({cfg.engine}@{cfg.host})")
    return {"id": conn_id, **cfg.dict(exclude={"password"})}

@app.get("/api/connections", tags=["Connections"])
def list_connections(user=Depends(require_auth)):
    store = load_store()
    return [
        {k: v for k, v in conn.items() if k != "password"}
        for conn in store["connections"].values()
    ]

@app.delete("/api/connections/{conn_id}", tags=["Connections"])
def delete_connection(conn_id: str, user=Depends(require_auth)):
    store = load_store()
    if conn_id not in store["connections"]:
        raise HTTPException(404, "Conexão não encontrada")
    name = store["connections"][conn_id].get("name", conn_id)
    del store["connections"][conn_id]
    save_store(store)
    active_connections.set(len(store["connections"]))
    audit_log("CONN_DELETE", user["sub"] if isinstance(user, dict) else "admin", conn_id, f"Conexão {name} removida", risk="medium")
    return {"success": True}

@app.post("/api/connections/test", tags=["Connections"])
def test_connection(cfg: ConnectionConfig):
    """Testa conexão retornando versão, latência, bancos disponíveis e topologia de replicação."""
    start = time.time()
    try:
        result = {"success": True, "engine": cfg.engine}
        if cfg.engine == "mysql":
            conn = connect_mysql(cfg)
            cur = conn.cursor()
            cur.execute("SELECT VERSION()")
            result["version"] = cur.fetchone()[0]
            cur.execute("SHOW DATABASES")
            result["databases"] = [r[0] for r in cur.fetchall()]
            # Detectar replicação
            try:
                cur.execute("SHOW SLAVE STATUS")
                slave = cur.fetchone()
                result["replication"] = {"role": "slave", "master": slave[1] if slave else None} if slave else {"role": "standalone"}
            except Exception:
                result["replication"] = {"role": "unknown"}
            # Detectar variáveis relevantes
            cur.execute("SHOW VARIABLES LIKE 'innodb_buffer_pool_size'")
            row = cur.fetchone()
            result["buffer_pool_mb"] = round(int(row[1]) / 1024 / 1024) if row else None
            conn.close()

        elif cfg.engine == "postgresql":
            conn = connect_pg(cfg)
            cur = conn.cursor()
            cur.execute("SELECT version()")
            result["version"] = cur.fetchone()[0].split(",")[0]
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate=false")
            result["databases"] = [r[0] for r in cur.fetchall()]
            result["replication"] = {"role": "unknown"}
            conn.close()

        elif cfg.engine == "mongodb":
            client = connect_mongo(cfg)
            info = client.server_info()
            result["version"] = f"MongoDB {info['version']}"
            result["databases"] = client.list_database_names()
            result["replication"] = {"role": "standalone"}
            client.close()

        else:
            raise HTTPException(400, f"Engine '{cfg.engine}' não suportado")

        result["latency_ms"] = round((time.time() - start) * 1000)
        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/api/connections/{conn_id}/databases", tags=["Connections"])
def list_databases(conn_id: str, user=Depends(require_auth)):
    """Lista bancos usando credenciais salvas (senha não exposta ao frontend)."""
    cfg = get_conn_by_id(conn_id)
    start = time.time()
    try:
        if cfg.engine == "mysql":
            conn = connect_mysql(cfg)
            cur = conn.cursor()
            cur.execute("SELECT VERSION()")
            version = cur.fetchone()[0]
            cur.execute("SHOW DATABASES")
            databases = [r[0] for r in cur.fetchall()]
            conn.close()
        elif cfg.engine == "postgresql":
            conn = connect_pg(cfg)
            cur = conn.cursor()
            cur.execute("SELECT version()")
            version = cur.fetchone()[0].split(",")[0]
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate=false")
            databases = [r[0] for r in cur.fetchall()]
            conn.close()
        elif cfg.engine == "mongodb":
            client = connect_mongo(cfg)
            info = client.server_info()
            version = f"MongoDB {info['version']}"
            databases = client.list_database_names()
            client.close()
        else:
            raise HTTPException(400, f"Engine '{cfg.engine}' não suportado")
        return {
            "success": True,
            "engine": cfg.engine,
            "version": version,
            "databases": databases,
            "latency_ms": round((time.time() - start) * 1000),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/api/connections/{conn_id}/tables/{database}", tags=["Connections"])
def list_tables(conn_id: str, database: str, user=Depends(require_auth)):
    cfg = get_conn_by_id(conn_id)
    cfg.database = database
    try:
        if cfg.engine == "mysql":
            conn = connect_mysql(cfg)
            cur = conn.cursor()
            cur.execute(f"USE `{database}`")
            cur.execute("SHOW TABLE STATUS")
            tables = [{"name": r[0], "rows": r[4] or 0, "size_mb": round(((r[6] or 0) + (r[8] or 0)) / 1024 / 1024, 3), "engine": r[1]} for r in cur.fetchall()]
            conn.close()

        elif cfg.engine == "postgresql":
            conn = connect_pg(cfg)
            cur = conn.cursor()
            cur.execute("SELECT tablename, pg_total_relation_size(quote_ident(tablename)) FROM pg_tables WHERE schemaname='public'")
            tables = []
            for r in cur.fetchall():
                cur2 = conn.cursor()
                try:
                    cur2.execute(f"SELECT COUNT(*) FROM {r[0]}")
                    rows = cur2.fetchone()[0]
                except Exception:
                    rows = 0
                tables.append({"name": r[0], "rows": rows, "size_mb": round(r[1] / 1024 / 1024, 3), "engine": "PostgreSQL"})
            conn.close()

        elif cfg.engine == "mongodb":
            client = connect_mongo(cfg)
            db = client[database]
            tables = []
            for col in db.list_collection_names():
                try:
                    stats = db.command("collStats", col)
                    tables.append({"name": col, "rows": stats.get("count", 0), "size_mb": round(stats.get("size", 0) / 1024 / 1024, 3), "engine": "MongoDB"})
                except Exception:
                    tables.append({"name": col, "rows": 0, "size_mb": 0, "engine": "MongoDB"})
            client.close()

        else:
            tables = []

        return {"success": True, "tables": tables, "count": len(tables)}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── ER Diagram helpers ────────────────────────────────────────────────────────

def _resolve_table_ref(name: str, table_map: dict) -> Optional[str]:
    """Resolve nome de tabela referenciada (singular/plural, case-insensitive)."""
    key = name.lower().strip()
    if not key:
        return None
    if key in table_map:
        return table_map[key]
    if key.endswith("s") and key[:-1] in table_map:
        return table_map[key[:-1]]
    if (key + "s") in table_map:
        return table_map[key + "s"]
    if key.endswith("es") and key[:-2] in table_map:
        return table_map[key[:-2]]
    return None


def _infer_mysql_fk_candidates(column: str) -> list:
    """Extrai possíveis nomes de tabela a partir do nome da coluna."""
    col = column.strip()
    if not col:
        return []
    lower = col.lower()
    candidates = []
    if lower.startswith("id_"):
        candidates.append(lower[3:])
    elif lower.startswith("fk_"):
        candidates.append(lower[3:])
    elif lower.endswith("_id"):
        candidates.append(lower[:-3])
    elif lower.endswith("id") and len(lower) > 2:
        base = lower[:-2].rstrip("_")
        if base:
            candidates.append(base)
    # cod_empresa, idEmpresa → normalizar camelCase
    parts = re.split(r"[_]", col)
    if len(parts) >= 2 and parts[0].lower() in ("id", "fk", "cod", "cd", "idref"):
        candidates.append("_".join(parts[1:]).lower())
    return list(dict.fromkeys(c for c in candidates if c))


def _build_mysql_er_diagram(conn, database: str) -> dict:
    """FKs formais + vínculos inferidos por convenção de nomenclatura."""
    cur = conn.cursor()
    cur.execute(f"SHOW TABLE STATUS FROM `{database}`")
    tables = [{"name": r[0], "rows": r[4] or 0, "engine": r[1]} for r in cur.fetchall()]
    table_map = {t["name"].lower(): t["name"] for t in tables}

    cur.execute("""
        SELECT kcu.TABLE_NAME, kcu.COLUMN_NAME, kcu.CONSTRAINT_NAME,
               kcu.REFERENCED_TABLE_NAME, kcu.REFERENCED_COLUMN_NAME
        FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
        INNER JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
          ON kcu.CONSTRAINT_SCHEMA = tc.CONSTRAINT_SCHEMA
         AND kcu.TABLE_NAME = tc.TABLE_NAME
         AND kcu.CONSTRAINT_NAME = tc.CONSTRAINT_NAME
         AND tc.CONSTRAINT_TYPE = 'FOREIGN KEY'
        WHERE kcu.TABLE_SCHEMA = %s AND kcu.REFERENCED_TABLE_NAME IS NOT NULL
    """, (database,))
    formal = [
        {
            "table": r[0], "column": r[1], "constraint": r[2],
            "ref_table": r[3], "ref_column": r[4], "inferred": False,
        }
        for r in cur.fetchall()
    ]

    cur.execute("""
        SELECT TABLE_NAME, COLUMN_NAME, COLUMN_KEY
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = %s
        ORDER BY TABLE_NAME, ORDINAL_POSITION
    """, (database,))
    columns_by_table = {}
    pk_by_table = {}
    for table, column, col_key in cur.fetchall():
        columns_by_table.setdefault(table, []).append(column)
        if col_key == "PRI":
            pk_by_table.setdefault(table, []).append(column)

    seen = {(fk["table"], fk["column"], fk["ref_table"]) for fk in formal}
    inferred = []

    for table, cols in columns_by_table.items():
        pks = set(pk_by_table.get(table, []))
        for column in cols:
            if column in pks:
                continue
            for candidate in _infer_mysql_fk_candidates(column):
                ref_table = _resolve_table_ref(candidate, table_map)
                if not ref_table or ref_table == table:
                    continue
                ref_pk = pk_by_table.get(ref_table, ["id"])
                ref_column = ref_pk[0] if ref_pk else "id"
                key = (table, column, ref_table)
                if key in seen:
                    continue
                seen.add(key)
                inferred.append({
                    "table": table,
                    "column": column,
                    "constraint": f"inferred_{table}_{column}",
                    "ref_table": ref_table,
                    "ref_column": ref_column,
                    "inferred": True,
                })

    all_links = formal + inferred
    linked_names = set()
    for fk in all_links:
        linked_names.add(fk["table"])
        linked_names.add(fk["ref_table"])

    return {
        "success": True,
        "tables": tables,
        "foreign_keys": all_links,
        "stats": {
            "total_tables": len(tables),
            "linked_tables": len(linked_names),
            "formal_fks": len(formal),
            "inferred_fks": len(inferred),
        },
    }


# ── Routes: ER Diagram ─────────────────────────────────────────────────────────

@app.get("/api/er-diagram/{conn_id}/{database}", tags=["Engineering"])
def get_er_diagram(conn_id: str, database: str, user=Depends(require_auth)):
    """Retorna estrutura de FK (formais + inferidas) para diagrama ER interativo."""
    cfg = get_conn_by_id(conn_id)
    cfg.database = database
    try:
        if cfg.engine == "mysql":
            conn = connect_mysql(cfg)
            result = _build_mysql_er_diagram(conn, database)
            conn.close()
            return result
        else:
            return {"success": True, "tables": [], "foreign_keys": [], "stats": {}, "note": "ER diagram available for MySQL only"}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── Routes: Backup ─────────────────────────────────────────────────────────────

@app.post("/api/backups/trigger", tags=["Backup"])
def trigger_backup(cfg: BackupTrigger, user=Depends(require_auth)):
    """Dispara backup. Se Celery disponível, enfileira como task assíncrona."""
    conn = get_conn_by_id(cfg.connection_id)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = cfg.output_name or f"{cfg.database}_{ts}"

    audit_log("BACKUP_TRIGGER", user["sub"] if isinstance(user, dict) else "admin",
              cfg.connection_id, f"Backup {cfg.backup_type} de {cfg.database}", risk="low")

    force_sync = os.getenv("BACKUP_FORCE_SYNC", "").lower() in ("1", "true", "yes")
    if CELERY_AVAILABLE and not force_sync:
        try:
            from tasks import run_backup_task
            task = run_backup_task.delay(cfg.dict(), conn.dict())
            return {
                "task_id": task.id, "status": "queued",
                "database": cfg.database, "type": cfg.backup_type,
            }
        except Exception as exc:
            log.warning("celery_enqueue_failed", error=str(exc))

    result = _run_backup_sync(conn, cfg, name, ts)
    backup_total.labels(engine=conn.engine, status="success").inc()
    backup_size_bytes.observe(result.get("size_bytes", 0))
    return {**result, "status": "success"}

def _run_backup_sync(conn: ConnectionConfig, cfg: BackupTrigger, name: str, ts: str) -> dict:
    """Executa backup sincronamente (fallback sem Celery)."""
    if conn.engine == "mysql":
        outfile = os.path.join(BACKUP_DIR, f"{name}.sql")
        cnf_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".cnf", delete=False) as cnf:
                cnf.write(
                    "[mysqldump]\n"
                    f"host={conn.host}\nport={conn.port}\nuser={conn.user}\npassword={conn.password}\n"
                )
                ssl_mode_env = os.getenv("MYSQLDUMP_SSL_MODE", "DISABLED").strip().upper()
                extra_cli = os.getenv("MYSQLDUMP_EXTRA_ARGS", "").strip()
                if not extra_cli and ssl_mode_env not in ("DEFAULT", "SERVER", "AUTO"):
                    cnf.write("ssl=0\nssl-verify-server-cert=false\n")
                cnf_path = cnf.name
            last_stderr = ""
            proc = None
            for ssl_args in _mysqldump_ssl_arg_variants():
                cmd = [
                    "mysqldump",
                    f"--defaults-extra-file={cnf_path}",
                ] + ssl_args + [
                    "--single-transaction", "--routines", "--triggers",
                    "--hex-blob", cfg.database,
                ]
                if cfg.tables:
                    cmd.extend(cfg.tables)
                with open(outfile, "w", encoding="utf-8") as f:
                    proc = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=600)
                if proc.returncode == 0:
                    try:
                        ver = _mysql_select_version(conn)
                        _write_mysql_backup_meta(outfile, conn, cfg.database, cfg.backup_type, cfg.tables, "native", ver)
                    except Exception as ex:
                        log.warning("backup_meta_write_failed", error=str(ex))
                    break
                last_stderr = proc.stderr.decode(errors="replace")
            if proc is None or proc.returncode != 0:
                raise HTTPException(400, last_stderr or "mysqldump falhou")
        except FileNotFoundError:
            return _mysql_python_backup(conn, cfg.database, cfg.tables, outfile, name, ts)
        finally:
            if cnf_path and os.path.exists(cnf_path):
                os.unlink(cnf_path)

    elif conn.engine == "postgresql":
        outfile = os.path.join(BACKUP_DIR, f"{name}.sql")
        env = os.environ.copy()
        env["PGPASSWORD"] = conn.password
        cmd = ["pg_dump", f"-h{conn.host}", f"-p{conn.port}", f"-U{conn.user}", "--format=plain"]
        if cfg.tables:
            for t in cfg.tables:
                cmd += ["-t", t]
        cmd.append(cfg.database)
        try:
            with open(outfile, "w", encoding="utf-8") as f:
                proc = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, env=env, timeout=600)
            if proc.returncode != 0:
                raise HTTPException(400, proc.stderr.decode())
        except FileNotFoundError:
            return _pg_python_backup(conn, cfg.database, cfg.tables, outfile, name, ts)

    elif conn.engine == "mongodb":
        outfile = os.path.join(BACKUP_DIR, f"{name}.json")
        return _mongo_python_backup(conn, cfg.database, cfg.tables, outfile, name, ts)

    else:
        raise HTTPException(400, f"Engine '{conn.engine}' não suportado")

    size = os.path.getsize(outfile)
    return {
        "success": True, "file": os.path.basename(outfile),
        "size_bytes": size, "size_mb": round(size / 1024 / 1024, 3),
        "tables": cfg.tables or ["(todas)"], "database": cfg.database,
        "engine": conn.engine, "timestamp": ts, "method": "native"
    }

def _mysql_python_backup(cfg: ConnectionConfig, database: str, tables, outfile: str, name: str, ts: str) -> dict:
    conn = connect_mysql(cfg)
    cur = conn.cursor()
    cur.execute("SELECT VERSION()")
    mysql_ver = (cur.fetchone() or ("unknown",))[0]
    cur.execute(f"USE `{database}`")
    if not tables:
        cur.execute("SHOW TABLES")
        tables = [r[0] for r in cur.fetchall()]

    lines = [
        "-- MySQL dump (VaultDB python fallback)",
        f"-- Server version:\t{mysql_ver}",
        "-- VaultDB Security Suite Backup",
        f"-- Database: {database}",
        f"-- Generated: {datetime.now().isoformat()}",
        f"-- Engine: MySQL (Python pure fallback)",
        "", "SET FOREIGN_KEY_CHECKS=0;", "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';", ""
    ]
    for table in tables:
        cur.execute(f"SHOW CREATE TABLE `{table}`")
        row = cur.fetchone()
        lines += [f"\n-- Table: {table}", f"DROP TABLE IF EXISTS `{table}`;", row[1] + ";", ""]
        cur.execute(f"SELECT * FROM `{table}`")
        for row in cur.fetchall():
            vals = []
            for v in row:
                if v is None: vals.append("NULL")
                elif isinstance(v, (int, float)): vals.append(str(v))
                else: vals.append("'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'")
            lines.append(f"INSERT INTO `{table}` VALUES ({', '.join(vals)});")
    lines += ["", "SET FOREIGN_KEY_CHECKS=1;"]
    conn.close()

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    try:
        ver = _mysql_select_version(cfg)
        _write_mysql_backup_meta(outfile, cfg, database, "python_fallback", tables, "python", ver)
    except Exception as ex:
        log.warning("backup_meta_write_failed", error=str(ex))
    size = os.path.getsize(outfile)
    return {"success": True, "file": os.path.basename(outfile), "size_bytes": size,
            "size_mb": round(size / 1024 / 1024, 3), "tables": tables,
            "database": database, "engine": "mysql", "timestamp": ts, "method": "python"}

def _pg_python_backup(cfg: ConnectionConfig, database: str, tables, outfile: str, name: str, ts: str) -> dict:
    conn = connect_pg(cfg)
    cur = conn.cursor()
    if not tables:
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        tables = [r[0] for r in cur.fetchall()]
    lines = ["-- VaultDB PostgreSQL Backup", f"-- Database: {database}", f"-- Generated: {datetime.now().isoformat()}", ""]
    for table in tables:
        cur.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}' ORDER BY ordinal_position")
        cols = [r[0] for r in cur.fetchall()]
        lines += [f"\n-- Table: {table}", f"TRUNCATE TABLE {table} CASCADE;"]
        cur.execute(f"SELECT * FROM {table}")
        for row in cur.fetchall():
            vals = []
            for v in row:
                if v is None: vals.append("NULL")
                elif isinstance(v, bool): vals.append("TRUE" if v else "FALSE")
                elif isinstance(v, (int, float)): vals.append(str(v))
                else: vals.append("'" + str(v).replace("'", "''") + "'")
            lines.append(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(vals)});")
    conn.close()
    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    size = os.path.getsize(outfile)
    return {"success": True, "file": os.path.basename(outfile), "size_bytes": size,
            "size_mb": round(size / 1024 / 1024, 3), "tables": tables,
            "database": database, "engine": "postgresql", "timestamp": ts, "method": "python"}

def _mongo_python_backup(cfg: ConnectionConfig, database: str, collections, outfile: str, name: str, ts: str) -> dict:
    client = connect_mongo(cfg)
    db = client[database]
    if not collections:
        collections = db.list_collection_names()
    data = {"database": database, "timestamp": datetime.now().isoformat(), "collections": {}}
    for col in collections:
        data["collections"][col] = list(db[col].find({}, {"_id": 0}))
    client.close()
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(data, f, default=str, indent=2)
    size = os.path.getsize(outfile)
    return {"success": True, "file": os.path.basename(outfile), "size_bytes": size,
            "size_mb": round(size / 1024 / 1024, 3), "tables": collections,
            "database": database, "engine": "mongodb", "timestamp": ts, "method": "python"}

@app.get("/api/backups/task/{task_id}/status", tags=["Backup"])
def backup_task_status(task_id: str, user=Depends(require_auth)):
    """Status de backup assíncrono (Celery)."""
    if not CELERY_AVAILABLE:
        raise HTTPException(501, "Celery não disponível")
    from celery.result import AsyncResult
    res = AsyncResult(task_id, app=celery_app)
    if res.state in ("PENDING", "RECEIVED", "STARTED", "RETRY"):
        return {"status": "running", "task_id": task_id, "state": res.state}
    if res.state == "SUCCESS":
        result = res.result if isinstance(res.result, dict) else {}
        return {"status": "success", "task_id": task_id, **result}
    if res.state == "FAILURE":
        err = str(res.info) if res.info else "Falha no backup"
        return {"status": "failure", "task_id": task_id, "error": err}
    return {"status": res.state.lower(), "task_id": task_id}


@app.get("/api/backups", tags=["Backup"])
def list_backups(user=Depends(require_auth)):
    files = []
    for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if f.startswith("."):
            continue
        path = os.path.join(BACKUP_DIR, f)
        if os.path.isfile(path):
            stat = os.stat(path)
            files.append({
                "file": f, "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / 1024 / 1024, 3),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "checksum": hashlib.md5(f.encode()).hexdigest()[:8]
            })
    return {"backups": files, "total": len(files)}

@app.get("/api/backups/{filename}/download", tags=["Backup"])
def download_backup(filename: str, user=Depends(require_auth)):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Arquivo não encontrado")
    audit_log("BACKUP_DOWNLOAD", user["sub"] if isinstance(user, dict) else "admin",
              filename, f"Download do backup {filename}", risk="medium")
    return FileResponse(path, filename=filename, media_type="application/octet-stream")

@app.delete("/api/backups/{filename}", tags=["Backup"])
def delete_backup(filename: str, user=Depends(require_auth)):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Arquivo não encontrado")
    os.remove(path)
    audit_log("BACKUP_DELETE", user["sub"] if isinstance(user, dict) else "admin",
              filename, f"Backup {filename} deletado", risk="high")
    return {"success": True}

# ── Routes: Restore (Workflow de Aprovação) ────────────────────────────────────


def _find_pending_restore(token: str):
    store = load_store()
    for rid, req in store["restore_requests"].items():
        if req["token"] == token and req["status"] == "pending":
            return rid, req
    return None, None


def _html_restore_page(title: str, inner: str, status_code: int = 200) -> HTMLResponse:
    body = f"""<!DOCTYPE html>
<html lang="pt"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{html.escape(title)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;background:#0f172a;color:#e2e8f0;line-height:1.5;}}
h1{{font-size:1.25rem;color:#f8fafc;}}
button{{background:#f59e0b;color:#111;padding:.65rem 1.1rem;border:none;border-radius:8px;font-weight:600;cursor:pointer;margin-top:1rem;font-size:1rem;}}
a{{color:#38bdf8;}}
pre{{background:#1e293b;padding:0.75rem;border-radius:6px;overflow:auto;font-size:0.85rem;}}
</style></head><body><h1>{html.escape(title)}</h1>{inner}</body></html>"""
    return HTMLResponse(body, status_code=status_code)


def _approve_confirmation_html(token: str, request: Request) -> HTMLResponse:
    """Página de confirmação (GET seguro): formulário POST com token no corpo."""
    _rid, req = _find_pending_restore(token)
    if not req:
        return _html_restore_page(
            "Aprovação indisponível",
            "<p>Token inválido ou esta solicitação já foi processada.</p>",
            status_code=404,
        )
    base = str(request.base_url).rstrip("/")
    esc = html.escape
    t_attr = html.escape(token, quote=True)
    inner = f"""<p><strong>Backup:</strong> {esc(req['backup_file'])} → <strong>banco:</strong> {esc(req['database'])}</p>
<p><strong>Solicitante:</strong> {esc(req.get('requestor') or '')}</p>
<p><strong>Justificativa:</strong> {esc((req.get('justification') or '')[:500])}</p>
<form method="post" action="{esc(base + '/api/restore/approve-submit')}">
<input type="hidden" name="token" value="{t_attr}"/>
<button type="submit">Confirmar aprovação e executar restore</button>
</form>
<p style="margin-top:1.5rem;font-size:0.88rem;color:#94a3b8">Este fluxo evita erro 405 ao abrir o link diretamente no navegador. No painel VaultDB use o botão «Aprovar» (POST autenticado).</p>"""
    return _html_restore_page("Aprovar restore — VaultDB", inner)


def _approve_restore_execute(token: str) -> dict:
    """Marca aprovado, executa restore, devolve dict JSON ou levanta HTTPException."""
    req_id, request = _find_pending_restore(token)
    if not request:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token inválido ou solicitação já processada")

    store = load_store()
    store["restore_requests"][req_id]["status"] = "approved"
    store["restore_requests"][req_id]["approved_at"] = datetime.now().isoformat()
    save_store(store)

    try:
        conn = get_conn_by_id(request["connection_id"])
        result = _run_restore_sync(conn, request["database"], request["backup_file"], request.get("tables"))
        store = load_store()
        store["restore_requests"][req_id]["status"] = "executed"
        store["restore_requests"][req_id]["executed_at"] = datetime.now().isoformat()
        save_store(store)
        audit_log(
            "RESTORE_EXECUTE",
            request["requestor_user"],
            request["connection_id"],
            f"Restore executado: {request['backup_file']} → {request['database']}",
            risk="critical",
        )
        restore_requests.labels(status="executed").inc()
        return {"success": True, "message": "Restore executado com sucesso", **result}
    except HTTPException:
        raise
    except Exception as e:
        store = load_store()
        store["restore_requests"][req_id]["status"] = "failed"
        save_store(store)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(e)) from e


@app.post("/api/restore/request", tags=["Restore"])
def request_restore(cfg: RestoreRequest, request: Request, user=Depends(require_auth)):
    """
    Cria uma solicitação de restore PENDENTE.
    A execução real só ocorre após aprovação (POST com token — painel ou página HTML).
    REGRA INFLEXÍVEL: nenhum restore é executado sem trilha de auditoria.
    """
    token = secrets.token_urlsafe(32)
    request_id = secrets.token_hex(12)
    store = load_store()
    store["restore_requests"][request_id] = {
        "id": request_id,
        "token": token,
        "status": "pending",  # pending | approved | rejected | executed
        "connection_id": cfg.connection_id,
        "database": cfg.database,
        "backup_file": cfg.backup_file,
        "tables": cfg.tables,
        "requestor": cfg.requestor_email,
        "requestor_user": user["sub"] if isinstance(user, dict) else "admin",
        "justification": cfg.justification,
        "mask_lgpd": cfg.mask_lgpd,
        "created": datetime.now().isoformat(),
        "approved_at": None,
        "executed_at": None,
    }
    save_store(store)
    restore_requests.labels(status="pending").inc()
    audit_log(
        "RESTORE_REQUEST",
        user["sub"] if isinstance(user, dict) else "admin",
        cfg.connection_id,
        f"Restore solicitado: {cfg.backup_file} → {cfg.database}",
        risk="critical",
    )

    base = str(request.base_url).rstrip("/")
    approval_url = f"{base}/api/restore/confirm?token={quote(token, safe='')}"
    email_sent = _send_approval_email(
        cfg.requestor_email, request_id, cfg.backup_file, cfg.database, cfg.justification, approval_url
    )

    if email_sent:
        msg = "Solicitação criada. Foi enviado um e-mail com o link de aprovação."
    else:
        msg = (
            "Solicitação criada. E-mail de aprovação não foi enviado (SMTP incompleto ou indisponível). "
            "Use o botão «Aprovar» no painel (Restaurar) ou abra o link de aprovação no navegador e confirme."
        )

    return {
        "request_id": request_id,
        "status": "pending",
        "message": msg,
        "approval_url": approval_url,
        "email_sent": email_sent,
    }


@app.get("/api/restore/confirm", tags=["Restore"])
def approve_restore_confirm(request: Request, token: str = Query(..., description="Token da solicitação de restore")):
    """Abrir no navegador (GET): link enviado por e-mail / copiado do painel — sem erro 405."""
    return _approve_confirmation_html(token, request)


@app.get("/api/restore/approve/{token}", tags=["Restore"])
def approve_restore_page_legacy(token: str, request: Request):
    """Compatibilidade com links antigos /api/restore/approve/{token}."""
    return _approve_confirmation_html(token, request)


@app.post("/api/restore/approve-submit", tags=["Restore"])
async def approve_restore_submit(request: Request):
    """Formulário HTML (application/x-www-form-urlencoded): token no corpo, não no path."""
    form = await request.form()
    token = (form.get("token") or "").strip()
    if not token:
        return _html_restore_page("Erro", "<p>Token em falta no formulário.</p>", status_code=400)
    ct = (request.headers.get("content-type") or "").lower()
    want_json = "application/json" in ct
    try:
        out = _approve_restore_execute(token)
    except HTTPException as exc:
        if want_json:
            raise exc
        return _html_restore_page(
            "Erro na aprovação",
            f"<p>{html.escape(str(exc.detail))}</p><p><a href=\"/\">Voltar ao VaultDB</a></p>",
            status_code=exc.status_code,
        )
    if want_json:
        return out
    detail = html.escape(json.dumps(out, indent=2, ensure_ascii=False))
    inner = f"""<p style="color:#86efac">{html.escape(out.get('message', 'OK'))}</p>
<pre>{detail}</pre>
<p><a href="/">Voltar ao VaultDB</a></p>"""
    return _html_restore_page("Restore concluído", inner)


@app.post("/api/restore/approve/{token}", tags=["Restore"])
def approve_restore(request: Request, token: str):
    """Painel (JSON) ou formulário HTML da página de confirmação."""
    ct = (request.headers.get("content-type") or "").lower()
    want_json = "application/json" in ct

    try:
        out = _approve_restore_execute(token)
    except HTTPException as exc:
        if want_json:
            raise exc
        return _html_restore_page(
            "Erro na aprovação",
            f"<p>{html.escape(str(exc.detail))}</p><p><a href=\"/\">Voltar ao VaultDB</a></p>",
            status_code=exc.status_code,
        )

    if want_json:
        return out

    detail = html.escape(json.dumps(out, indent=2, ensure_ascii=False))
    inner = f"""<p style="color:#86efac">{html.escape(out.get('message', 'OK'))}</p>
<pre>{detail}</pre>
<p><a href="/">Voltar ao VaultDB</a></p>"""
    return _html_restore_page("Restore concluído", inner)


@app.get("/api/restore/requests", tags=["Restore"])
def list_restore_requests(user=Depends(require_auth)):
    store = load_store()
    return list(store["restore_requests"].values())


@app.get("/api/backups/{filename}/meta", tags=["Backup"])
def get_backup_meta(filename: str, user=Depends(require_auth)):
    """Metadados do backup (versão MySQL, etc.) — ficheiro .meta.json ou cabeçalho do .sql."""
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Backup não encontrado")
    meta = _load_backup_meta(filename)
    if not meta.get("mysql_version") and filename.endswith(".sql"):
        meta = {**meta, **_peek_mysql_dump_header(path)}
    return meta


@app.post("/api/linux-prepare/script", tags=["LinuxPrepare"])
def linux_prepare_script(req: LinuxPrepareScriptRequest, user=Depends(require_auth)):
    """
    Módulo DR: gera script bash para correr no Linux de destino (sudo): instala MariaDB/MySQL via apt,
    cria o banco e o utilizador com as mesmas credenciais da conexão VaultDB.
    """
    conn = get_conn_by_id(req.connection_id)
    if conn.engine != "mysql":
        raise HTTPException(400, "Apenas conexões MySQL/MariaDB nesta versão")
    path = os.path.join(BACKUP_DIR, req.backup_file)
    if not os.path.isfile(path):
        raise HTTPException(404, "Ficheiro de backup não encontrado")
    meta = _load_backup_meta(req.backup_file)
    if not meta.get("mysql_version") and req.backup_file.endswith(".sql"):
        meta = {**meta, **_peek_mysql_dump_header(path)}
    ver = meta.get("mysql_version") or "desconhecida"
    dbn = req.target_database.replace("`", "").strip()
    if not dbn:
        raise HTTPException(400, "target_database inválido")
    script = build_linux_mysql_prepare_script(
        mysql_version_hint=ver,
        target_database=dbn,
        app_user=conn.user,
        app_password=conn.password,
        package_flavor=req.package_flavor,
        install_server=req.install_server,
    )
    audit_log(
        "LINUX_PREP_SCRIPT",
        user["sub"] if isinstance(user, dict) else "admin",
        req.backup_file,
        f"Script Linux gerado → {dbn} (ref. {ver})",
        risk="medium",
    )
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", dbn)[:40]
    return {
        "script": script,
        "filename": f"vaultdb-prepare-{safe}.sh",
        "detected_version": ver,
        "package_flavor": _package_flavor_from_version(ver, req.package_flavor),
        "note": "O script contém credenciais em base64 (SQL). Guarde com segurança. Revise a versão do servidor em produção.",
    }


def _run_restore_sync(conn: ConnectionConfig, database: str, backup_file: str, tables=None) -> dict:
    path = os.path.join(BACKUP_DIR, backup_file)
    if not os.path.exists(path):
        raise HTTPException(404, f"Arquivo {backup_file} não encontrado")

    if conn.engine == "mysql":
        db_conn = connect_mysql(conn)
        _mysql_ensure_restore_privileges(db_conn, database, conn.user, conn.password)
        db_conn.close()

        cli_out = _run_mysql_restore_via_cli(conn, database, path)
        if cli_out is not None:
            return cli_out

        import pymysql

        db_safe = database.replace("`", "").replace("'", "")
        db_conn = pymysql.connect(
            host=conn.host,
            port=conn.port,
            user=conn.user,
            password=conn.password,
            database=db_safe,
            connect_timeout=12,
            charset="utf8mb4",
            autocommit=True,
        )
        cur = db_conn.cursor()
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            sql = f.read()
        stmts = [s.strip() for s in sql.split(";") if s.strip() and not s.strip().startswith("--")]
        errors = []
        restored = 0
        for stmt in stmts:
            if _mysql_restore_stmt_should_skip(stmt):
                continue
            try:
                cur.execute(stmt)
                restored += 1
            except Exception as e:
                errors.append(str(e)[:200])
        db_conn.close()

    elif conn.engine == "postgresql":
        db_conn = connect_pg(conn)
        db_conn.autocommit = True
        cur = db_conn.cursor()
        with open(path, "r", encoding="utf-8") as f:
            sql = f.read()
        stmts = [s.strip() for s in sql.split(";") if s.strip() and not s.strip().startswith("--")]
        errors = []
        restored = 0
        for stmt in stmts:
            try:
                cur.execute(stmt)
                restored += 1
            except Exception as e:
                errors.append(str(e)[:120])
        db_conn.close()

    elif conn.engine == "mongodb":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        client = connect_mongo(conn)
        db = client[database]
        errors = []
        restored = 0
        for col_name, docs in data.get("collections", {}).items():
            if tables and col_name not in tables:
                continue
            try:
                db[col_name].delete_many({})
                if docs:
                    db[col_name].insert_many(docs)
                restored += len(docs)
            except Exception as e:
                errors.append(str(e)[:120])
        client.close()
    else:
        raise HTTPException(400, "Engine não suportado para restore")

    return {"database": database, "statements_executed": restored, "errors": errors[:5], "backup_file": backup_file}

# ── Routes: Schedules ──────────────────────────────────────────────────────────

@app.get("/api/schedules", tags=["Schedules"])
def list_schedules(user=Depends(require_auth)):
    store = load_store()
    return list(store["schedules"].values())

@app.post("/api/schedules", tags=["Schedules"])
def create_schedule(cfg: ScheduleCreate, user=Depends(require_auth)):
    store = load_store()
    sched_id = secrets.token_hex(8)
    store["schedules"][sched_id] = {
        **cfg.dict(), "id": sched_id,
        "created": datetime.now().isoformat(),
        "last_run": None, "next_run": None,
        "runs_total": 0, "runs_success": 0
    }
    save_store(store)
    audit_log("SCHEDULE_CREATE", user["sub"] if isinstance(user, dict) else "admin",
              cfg.connection_id, f"Schedule '{cfg.name}' ({cfg.cron_expression})")
    return store["schedules"][sched_id]

@app.delete("/api/schedules/{sched_id}", tags=["Schedules"])
def delete_schedule(sched_id: str, user=Depends(require_auth)):
    store = load_store()
    if sched_id not in store["schedules"]:
        raise HTTPException(404, "Schedule não encontrado")
    del store["schedules"][sched_id]
    save_store(store)
    return {"success": True}


# ── Routes: Settings (apenas admin) ───────────────────────────────────────────

@app.get("/api/settings", tags=["Settings"])
def api_get_settings(user=Depends(require_admin)):
    s = _settings_dict()
    host, port, u, pw = _smtp_credentials()
    tt = (s.get("telegram_token") or os.getenv("TELEGRAM_TOKEN") or "").strip()
    tc = (s.get("telegram_chat_id") or os.getenv("TELEGRAM_CHAT_ID") or "").strip()
    return {
        "smtp_host": (s.get("smtp_host") or "").strip() or (os.getenv("SMTP_HOST") or "").strip(),
        "smtp_port": port,
        "smtp_user": (s.get("smtp_user") or "").strip() or (os.getenv("SMTP_USER") or "").strip(),
        "smtp_pass_configured": bool(pw),
        "telegram_token_configured": bool(tt),
        "telegram_chat_id": tc,
    }


@app.put("/api/settings", tags=["Settings"])
def api_put_settings(body: SettingsUpdate, user=Depends(require_admin)):
    store = load_store()
    st = store.setdefault("settings", _default_store()["settings"])
    if body.smtp_host is not None:
        st["smtp_host"] = body.smtp_host.strip()
    if body.smtp_port is not None:
        st["smtp_port"] = int(body.smtp_port)
    if body.smtp_user is not None:
        st["smtp_user"] = body.smtp_user.strip()
    if body.smtp_pass is not None:
        if body.smtp_pass == "__CLEAR__":
            st["smtp_pass"] = ""
        elif body.smtp_pass != "":
            st["smtp_pass"] = body.smtp_pass
    if body.telegram_token is not None:
        if body.telegram_token == "__CLEAR__":
            st["telegram_token"] = ""
        else:
            st["telegram_token"] = body.telegram_token.strip()
    if body.telegram_chat_id is not None:
        st["telegram_chat_id"] = body.telegram_chat_id.strip()
    save_store(store)
    audit_log(
        "SETTINGS_UPDATE",
        user["sub"],
        "settings",
        "Configurações SMTP/Telegram atualizadas no painel",
        risk="high",
    )
    return api_get_settings(user)


@app.post("/api/settings/test-smtp", tags=["Settings"])
def api_test_smtp(body: SmtpTestRequest, user=Depends(require_admin)):
    host, port, u, pw = _smtp_credentials()
    if not host or not u:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Preencha SMTP (host e utilizador) em Configurações ou .env")
    to = body.to.strip()
    if not to or "@" not in to:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "E-mail destino inválido")
    try:
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText("Mensagem de teste do VaultDB Security Suite.\n\nSe recebeu, o SMTP está correto.", "plain", "utf-8")
        msg["Subject"] = "VaultDB — teste SMTP"
        msg["From"] = u
        msg["To"] = to
        with smtplib.SMTP(host, port, timeout=25) as smtp:
            smtp.ehlo()
            if port == 587:
                smtp.starttls()
                smtp.ehlo()
            if pw:
                smtp.login(u, pw)
            smtp.sendmail(u, [to], msg.as_string())
    except Exception as ex:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"Falha SMTP: {ex}") from ex
    audit_log("SMTP_TEST", user["sub"], to, "Teste de e-mail enviado", risk="low")
    return {"success": True, "message": f"E-mail de teste enviado para {to}"}


@app.get("/api/users", tags=["Settings"])
def api_list_users(user=Depends(require_admin)):
    store = load_store()
    return [
        {"username": name, "role": u.get("role", "viewer") if isinstance(u, dict) else "viewer"}
        for name, u in store.get("users", {}).items()
    ]


@app.post("/api/users", tags=["Settings"])
def api_create_user(body: UserCreate, user=Depends(require_admin)):
    uname = body.username.strip()
    if not re.match(r"^[a-zA-Z0-9_.-]{2,64}$", uname):
        raise HTTPException(400, "Nome de utilizador inválido (2–64 caracteres: letras, números, . _ -)")
    if body.role not in ("admin", "viewer"):
        raise HTTPException(400, "role deve ser admin ou viewer")
    store = load_store()
    users = store.setdefault("users", {})
    if uname in users:
        raise HTTPException(409, "Utilizador já existe")
    users[uname] = {
        "password_hash": hashlib.sha256(body.password.encode()).hexdigest(),
        "role": body.role,
    }
    save_store(store)
    audit_log("USER_CREATE", user["sub"], uname, f"Novo utilizador role={body.role}", risk="high")
    return {"username": uname, "role": body.role}


@app.delete("/api/users/{username}", tags=["Settings"])
def api_delete_user(username: str, user=Depends(require_admin)):
    if username == user.get("sub"):
        raise HTTPException(400, "Não pode remover a sua própria sessão")
    store = load_store()
    users = store.get("users") or {}
    if username not in users:
        raise HTTPException(404, "Utilizador não encontrado")
    admins = [n for n, u in users.items() if isinstance(u, dict) and u.get("role") == "admin"]
    if users[username].get("role") == "admin" and len(admins) <= 1:
        raise HTTPException(400, "Não pode remover o único administrador")
    del users[username]
    save_store(store)
    audit_log("USER_DELETE", user["sub"], username, "Utilizador removido", risk="high")
    return {"success": True}


@app.post("/api/users/{username}/password", tags=["Settings"])
def api_change_user_password(username: str, body: UserPasswordUpdate, user=Depends(require_admin)):
    store = load_store()
    users = store.get("users") or {}
    if username not in users:
        raise HTTPException(404, "Utilizador não encontrado")
    users[username]["password_hash"] = hashlib.sha256(body.password.encode()).hexdigest()
    save_store(store)
    audit_log("USER_PASSWORD", user["sub"], username, "Palavra-passe alterada", risk="high")
    return {"success": True}


# ── Routes: Audit ──────────────────────────────────────────────────────────────

@app.get("/api/audit", tags=["Audit"])
def get_audit_log(limit: int = 100, risk: Optional[str] = None, user=Depends(require_auth)):
    store = load_store()
    entries = store["audit"]
    if risk:
        entries = [e for e in entries if e.get("risk") == risk]
    return {"entries": list(reversed(entries))[:limit], "total": len(entries)}

# ── Routes: Alerts ─────────────────────────────────────────────────────────────

@app.post("/api/alerts/test", tags=["Alerts"])
def test_alert(body: AlertTest, user=Depends(require_auth)):
    result = _send_telegram(body.message)
    return {"sent": result, "message": body.message}

def _send_telegram(message: str) -> bool:
    s = _settings_dict()
    token = (s.get("telegram_token") or os.getenv("TELEGRAM_TOKEN") or "").strip()
    chat_id = (s.get("telegram_chat_id") or os.getenv("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id or not HTTPX_AVAILABLE:
        return False
    try:
        import httpx
        r = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": f"🛡️ VaultDB\n{message}", "parse_mode": "Markdown"},
            timeout=5
        )
        return r.status_code == 200
    except Exception:
        return False

def _settings_dict() -> dict:
    store = load_store()
    return store.get("settings") or _default_store()["settings"]


def _smtp_credentials() -> tuple:
    s = _settings_dict()
    host = (s.get("smtp_host") or os.getenv("SMTP_HOST") or "").strip()
    try:
        port = int(s.get("smtp_port") or int(os.getenv("SMTP_PORT", "587") or 587))
    except (TypeError, ValueError):
        port = 587
    user = (s.get("smtp_user") or os.getenv("SMTP_USER") or "").strip()
    password = (s.get("smtp_pass") or os.getenv("SMTP_PASS") or "").strip()
    return host, port, user, password


def _send_approval_email(to: str, req_id: str, backup_file: str, database: str, justification: str, url: str) -> bool:
    """Envia e-mail de aprovação se SMTP estiver completo (painel ou variáveis de ambiente)."""
    log.info(
        "approval_email_required",
        to=to,
        request_id=req_id,
        backup=backup_file,
        database=database,
        approval_url=url,
    )
    host, port, user, password = _smtp_credentials()
    if not host or not user:
        return False
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        body = (
            f"Pedido de restore VaultDB\n\n"
            f"ID: {req_id}\n"
            f"Backup: {backup_file}\n"
            f"Banco destino: {database}\n"
            f"Justificativa: {justification}\n\n"
            f"Para aprovar, abra no navegador (confirme na página):\n{url}\n"
        )
        msg = MIMEMultipart()
        msg["Subject"] = "VaultDB — Aprovar restore"
        msg["From"] = user
        msg["To"] = to
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.ehlo()
            if port == 587:
                smtp.starttls()
                smtp.ehlo()
            if password:
                smtp.login(user, password)
            smtp.sendmail(user, [to], msg.as_string())
        log.info("approval_email_sent", to=to, request_id=req_id)
        return True
    except Exception as ex:
        log.warning("approval_email_failed", error=str(ex)[:300])
        return False

# ── Routes: Metrics (Prometheus) ──────────────────────────────────────────────

@app.get("/metrics", tags=["Monitoring"])
def prometheus_metrics():
    return Response(generate_latest(), media_type="text/plain; version=0.0.4")

@app.get("/api/stats", tags=["Monitoring"])
def get_stats(user=Depends(require_auth)):
    store = load_store()
    files = [f for f in os.listdir(BACKUP_DIR) if not f.startswith(".") and os.path.isfile(os.path.join(BACKUP_DIR, f))]
    total_bytes = sum(os.path.getsize(os.path.join(BACKUP_DIR, f)) for f in files)
    return {
        "connections": len(store["connections"]),
        "backups": len(files),
        "storage_bytes": total_bytes,
        "storage_mb": round(total_bytes / 1024 / 1024, 2),
        "schedules": len(store["schedules"]),
        "restore_requests": len(store["restore_requests"]),
        "audit_entries": len(store["audit"]),
        "pending_restores": sum(1 for r in store["restore_requests"].values() if r["status"] == "pending")
    }

# ── Root ────────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    index = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return {"app": "VaultDB Security Suite", "version": "2.0.0", "docs": "/api/docs"}

# Registra tasks Celery ao carregar o módulo (worker e director)
if CELERY_AVAILABLE:
    try:
        import tasks  # noqa: F401
    except ImportError:
        pass

# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  VaultDB Security Suite v2.0 — Director API")
    print("  http://localhost:8000  |  Docs: /api/docs")
    print("  Default: admin / vaultdb2024")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
