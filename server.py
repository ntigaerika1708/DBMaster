#!/usr/bin/env python3
"""
DBMaster Suite - Backend API
Instale as dependências: pip install fastapi uvicorn pymysql psycopg2-binary pyodbc pymongo
Execute: python server.py
Acesse: http://localhost:8000
"""

import asyncio
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="DBMaster Suite API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Models ───────────────────────────────────────────────────────────────────

class ConnectionConfig(BaseModel):
    engine: str        # mysql | postgresql | mssql | mongodb
    host: str
    port: int
    user: str
    password: str
    database: Optional[str] = None

class BackupConfig(BaseModel):
    connection: ConnectionConfig
    database: str
    tables: Optional[list[str]] = None  # None = backup full
    output_name: Optional[str] = None

class RestoreConfig(BaseModel):
    connection: ConnectionConfig
    database: str
    backup_file: str   # path do arquivo de backup
    tables: Optional[list[str]] = None  # None = restore completo

# ─── Diretório de backups ──────────────────────────────────────────────────────

BACKUP_DIR = os.path.join(os.path.dirname(__file__), "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

# ─── Helpers de conexão ────────────────────────────────────────────────────────

def get_mysql_conn(cfg: ConnectionConfig):
    try:
        import pymysql
        conn = pymysql.connect(
            host=cfg.host, port=cfg.port,
            user=cfg.user, password=cfg.password,
            database=cfg.database, connect_timeout=5,
            charset="utf8mb4"
        )
        return conn
    except ImportError:
        raise HTTPException(500, "pymysql não instalado: pip install pymysql")

def get_pg_conn(cfg: ConnectionConfig):
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=cfg.host, port=cfg.port,
            user=cfg.user, password=cfg.password,
            dbname=cfg.database, connect_timeout=5
        )
        return conn
    except ImportError:
        raise HTTPException(500, "psycopg2 não instalado: pip install psycopg2-binary")

def get_mssql_conn(cfg: ConnectionConfig):
    try:
        import pyodbc
        cs = (f"DRIVER={{ODBC Driver 17 for SQL Server}};"
              f"SERVER={cfg.host},{cfg.port};"
              f"DATABASE={cfg.database};"
              f"UID={cfg.user};PWD={cfg.password};Timeout=5")
        return pyodbc.connect(cs)
    except ImportError:
        raise HTTPException(500, "pyodbc não instalado: pip install pyodbc")

def get_mongo_client(cfg: ConnectionConfig):
    try:
        from pymongo import MongoClient
        uri = f"mongodb://{cfg.user}:{cfg.password}@{cfg.host}:{cfg.port}/"
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.server_info()
        return client
    except ImportError:
        raise HTTPException(500, "pymongo não instalado: pip install pymongo")

# ─── Rotas ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    index = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(index)

@app.post("/api/test-connection")
def test_connection(cfg: ConnectionConfig):
    """Testa conexão com o banco de dados."""
    try:
        start = time.time()
        if cfg.engine == "mysql":
            conn = get_mysql_conn(cfg)
            cur = conn.cursor()
            cur.execute("SELECT VERSION()")
            version = cur.fetchone()[0]
            cur.execute("SHOW DATABASES")
            databases = [r[0] for r in cur.fetchall()]
            conn.close()
        elif cfg.engine == "postgresql":
            conn = get_pg_conn(cfg)
            cur = conn.cursor()
            cur.execute("SELECT version()")
            version = cur.fetchone()[0].split(",")[0]
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
            databases = [r[0] for r in cur.fetchall()]
            conn.close()
        elif cfg.engine == "mssql":
            conn = get_mssql_conn(cfg)
            cur = conn.cursor()
            cur.execute("SELECT @@VERSION")
            version = cur.fetchone()[0].split("\n")[0]
            cur.execute("SELECT name FROM sys.databases")
            databases = [r[0] for r in cur.fetchall()]
            conn.close()
        elif cfg.engine == "mongodb":
            client = get_mongo_client(cfg)
            info = client.server_info()
            version = f"MongoDB {info['version']}"
            databases = client.list_database_names()
            client.close()
        else:
            raise HTTPException(400, f"Engine '{cfg.engine}' não suportado")

        elapsed = round((time.time() - start) * 1000)
        return {
            "success": True,
            "version": version,
            "databases": databases,
            "latency_ms": elapsed
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/list-tables")
def list_tables(cfg: ConnectionConfig):
    """Lista tabelas de um banco de dados."""
    if not cfg.database:
        raise HTTPException(400, "database é obrigatório")
    try:
        if cfg.engine == "mysql":
            conn = get_mysql_conn(cfg)
            cur = conn.cursor()
            cur.execute(f"USE `{cfg.database}`")
            cur.execute("SHOW TABLE STATUS")
            tables = []
            for r in cur.fetchall():
                tables.append({
                    "name": r[0],
                    "rows": r[4] or 0,
                    "size_mb": round(((r[6] or 0) + (r[8] or 0)) / 1024 / 1024, 2),
                    "engine": r[1] or "InnoDB"
                })
            conn.close()
        elif cfg.engine == "postgresql":
            conn = get_pg_conn(cfg)
            cur = conn.cursor()
            cur.execute("""
                SELECT tablename,
                       pg_size_pretty(pg_total_relation_size(quote_ident(tablename))),
                       pg_total_relation_size(quote_ident(tablename))
                FROM pg_tables
                WHERE schemaname = 'public'
                ORDER BY pg_total_relation_size(quote_ident(tablename)) DESC
            """)
            tables = []
            for r in cur.fetchall():
                cur2 = conn.cursor()
                cur2.execute(f"SELECT COUNT(*) FROM {r[0]}")
                rows = cur2.fetchone()[0]
                tables.append({
                    "name": r[0],
                    "rows": rows,
                    "size_mb": round(r[2] / 1024 / 1024, 2),
                    "engine": "PostgreSQL"
                })
            conn.close()
        elif cfg.engine == "mssql":
            conn = get_mssql_conn(cfg)
            cur = conn.cursor()
            cur.execute("""
                SELECT t.name,
                       SUM(p.rows),
                       SUM(a.total_pages) * 8 / 1024.0
                FROM sys.tables t
                JOIN sys.indexes i ON t.object_id = i.object_id
                JOIN sys.partitions p ON i.object_id = p.object_id AND i.index_id = p.index_id
                JOIN sys.allocation_units a ON p.partition_id = a.container_id
                GROUP BY t.name
            """)
            tables = [{"name": r[0], "rows": r[1] or 0, "size_mb": round(float(r[2] or 0), 2), "engine": "MSSQL"} for r in cur.fetchall()]
            conn.close()
        elif cfg.engine == "mongodb":
            client = get_mongo_client(cfg)
            db = client[cfg.database]
            tables = []
            for col in db.list_collection_names():
                stats = db.command("collStats", col)
                tables.append({
                    "name": col,
                    "rows": stats.get("count", 0),
                    "size_mb": round(stats.get("size", 0) / 1024 / 1024, 2),
                    "engine": "MongoDB"
                })
            client.close()
        else:
            raise HTTPException(400, "Engine não suportado")

        return {"success": True, "tables": tables}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/backup")
def run_backup(cfg: BackupConfig):
    """Executa backup do banco — full ou de tabelas específicas."""
    conn_cfg = cfg.connection
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = cfg.output_name or f"{cfg.database}_{ts}"
    
    try:
        if conn_cfg.engine == "mysql":
            outfile = os.path.join(BACKUP_DIR, f"{name}.sql")
            tables_arg = " ".join(cfg.tables) if cfg.tables else ""
            cmd = [
                "mysqldump",
                f"-h{conn_cfg.host}", f"-P{conn_cfg.port}",
                f"-u{conn_cfg.user}", f"-p{conn_cfg.password}",
                "--single-transaction", "--routines", "--triggers",
                cfg.database
            ]
            if cfg.tables:
                cmd.extend(cfg.tables)
            try:
                with open(outfile, "w") as f:
                    result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=300)
                if result.returncode != 0:
                    err = result.stderr.decode()
                    raise HTTPException(400, err)
            except FileNotFoundError:
                return _mysql_backup_python(conn_cfg, cfg.database, cfg.tables, outfile, name)

        elif conn_cfg.engine == "postgresql":
            outfile = os.path.join(BACKUP_DIR, f"{name}.sql")
            env = os.environ.copy()
            env["PGPASSWORD"] = conn_cfg.password
            cmd = [
                "pg_dump",
                f"-h{conn_cfg.host}", f"-p{conn_cfg.port}",
                f"-U{conn_cfg.user}", "--format=plain", "--no-password"
            ]
            if cfg.tables:
                for t in cfg.tables:
                    cmd += ["-t", t]
            cmd.append(cfg.database)
            try:
                with open(outfile, "w") as f:
                    result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, env=env, timeout=300)
                if result.returncode != 0:
                    err = result.stderr.decode()
                    raise HTTPException(400, err)
            except FileNotFoundError:
                return _pg_backup_python(conn_cfg, cfg.database, cfg.tables, outfile, name)

        elif conn_cfg.engine == "mongodb":
            outfile = os.path.join(BACKUP_DIR, f"{name}.json")
            return _mongo_backup_python(conn_cfg, cfg.database, cfg.tables, outfile, name)

        elif conn_cfg.engine == "mssql":
            outfile = os.path.join(BACKUP_DIR, f"{name}.sql")
            return _mssql_backup_python(conn_cfg, cfg.database, cfg.tables, outfile, name)

        else:
            raise HTTPException(400, "Engine não suportado")

        size = os.path.getsize(outfile)
        return {
            "success": True,
            "file": os.path.basename(outfile),
            "path": outfile,
            "size_bytes": size,
            "size_mb": round(size / 1024 / 1024, 2),
            "tables": cfg.tables or ["(todas)"],
            "database": cfg.database,
            "timestamp": ts
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


def _mysql_backup_python(cfg, database, tables, outfile, name):
    """Fallback: backup MySQL via pymysql puro."""
    conn = get_mysql_conn(cfg)
    cur = conn.cursor()
    cur.execute(f"USE `{database}`")
    
    if tables:
        target_tables = tables
    else:
        cur.execute("SHOW TABLES")
        target_tables = [r[0] for r in cur.fetchall()]

    lines = [
        f"-- DBMaster Suite Backup",
        f"-- Database: {database}",
        f"-- Generated: {datetime.now().isoformat()}",
        f"-- Engine: MySQL (Python fallback)",
        f"",
        f"SET FOREIGN_KEY_CHECKS=0;",
        f"SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';",
        f""
    ]

    for table in target_tables:
        cur.execute(f"SHOW CREATE TABLE `{table}`")
        row = cur.fetchone()
        create_sql = row[1]
        lines.append(f"\n-- Table: {table}")
        lines.append(f"DROP TABLE IF EXISTS `{table}`;")
        lines.append(create_sql + ";")
        lines.append("")

        cur.execute(f"SELECT * FROM `{table}`")
        rows = cur.fetchall()
        if rows:
            col_count = len(rows[0])
            for row in rows:
                vals = []
                for v in row:
                    if v is None:
                        vals.append("NULL")
                    elif isinstance(v, (int, float)):
                        vals.append(str(v))
                    else:
                        escaped = str(v).replace("'", "\\'").replace("\\", "\\\\")
                        vals.append(f"'{escaped}'")
                lines.append(f"INSERT INTO `{table}` VALUES ({', '.join(vals)});")
        lines.append("")

    lines.append("SET FOREIGN_KEY_CHECKS=1;")
    conn.close()

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    size = os.path.getsize(outfile)
    return {
        "success": True,
        "file": os.path.basename(outfile),
        "path": outfile,
        "size_bytes": size,
        "size_mb": round(size / 1024 / 1024, 2),
        "tables": target_tables,
        "database": database,
        "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "method": "python"
    }


def _pg_backup_python(cfg, database, tables, outfile, name):
    """Fallback: backup PostgreSQL via psycopg2 puro."""
    conn = get_pg_conn(cfg)
    cur = conn.cursor()

    if tables:
        target_tables = tables
    else:
        cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        target_tables = [r[0] for r in cur.fetchall()]

    lines = [
        f"-- DBMaster Suite Backup",
        f"-- Database: {database}",
        f"-- Generated: {datetime.now().isoformat()}",
        f"-- Engine: PostgreSQL (Python fallback)", ""
    ]

    for table in target_tables:
        cur.execute(f"SELECT column_name, data_type FROM information_schema.columns WHERE table_name='{table}' ORDER BY ordinal_position")
        cols = cur.fetchall()
        col_names = [c[0] for c in cols]

        lines.append(f"\n-- Table: {table}")
        lines.append(f"TRUNCATE TABLE {table} CASCADE;")
        cur.execute(f"SELECT * FROM {table}")
        rows = cur.fetchall()
        for row in rows:
            vals = []
            for v in row:
                if v is None:
                    vals.append("NULL")
                elif isinstance(v, bool):
                    vals.append("TRUE" if v else "FALSE")
                elif isinstance(v, (int, float)):
                    vals.append(str(v))
                else:
                    escaped = str(v).replace("'", "''")
                    vals.append(f"'{escaped}'")
            lines.append(f"INSERT INTO {table} ({', '.join(col_names)}) VALUES ({', '.join(vals)});")

    conn.close()
    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    size = os.path.getsize(outfile)
    return {
        "success": True, "file": os.path.basename(outfile), "path": outfile,
        "size_bytes": size, "size_mb": round(size / 1024 / 1024, 2),
        "tables": target_tables, "database": database,
        "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"), "method": "python"
    }


def _mongo_backup_python(cfg, database, tables, outfile, name):
    """Backup MongoDB via pymongo."""
    client = get_mongo_client(cfg)
    db = client[database]

    if tables:
        collections = tables
    else:
        collections = db.list_collection_names()

    backup_data = {}
    for col in collections:
        docs = list(db[col].find({}, {"_id": 0}))
        backup_data[col] = docs

    client.close()

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump({"database": database, "timestamp": datetime.now().isoformat(), "collections": backup_data}, f, default=str, indent=2)

    size = os.path.getsize(outfile)
    return {
        "success": True, "file": os.path.basename(outfile), "path": outfile,
        "size_bytes": size, "size_mb": round(size / 1024 / 1024, 2),
        "tables": collections, "database": database,
        "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"), "method": "python"
    }


def _mssql_backup_python(cfg, database, tables, outfile, name):
    """Backup SQL Server via pyodbc."""
    conn = get_mssql_conn(cfg)
    cur = conn.cursor()

    if tables:
        target_tables = tables
    else:
        cur.execute("SELECT name FROM sys.tables ORDER BY name")
        target_tables = [r[0] for r in cur.fetchall()]

    lines = [f"-- DBMaster Suite Backup\n-- Database: {database}\n-- Generated: {datetime.now().isoformat()}\n-- Engine: SQL Server\n"]
    for table in target_tables:
        cur.execute(f"SELECT * FROM [{table}]")
        cols = [desc[0] for desc in cur.description]
        lines.append(f"\n-- Table: {table}")
        for row in cur.fetchall():
            vals = ["NULL" if v is None else f"'{str(v)}'" for v in row]
            lines.append(f"INSERT INTO [{table}] ({', '.join(f'[{c}]' for c in cols)}) VALUES ({', '.join(vals)});")

    conn.close()
    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    size = os.path.getsize(outfile)
    return {
        "success": True, "file": os.path.basename(outfile), "path": outfile,
        "size_bytes": size, "size_mb": round(size / 1024 / 1024, 2),
        "tables": target_tables, "database": database,
        "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"), "method": "python"
    }


@app.post("/api/restore")
def run_restore(cfg: RestoreConfig):
    """Restaura backup em um banco de dados."""
    backup_path = os.path.join(BACKUP_DIR, cfg.backup_file)
    if not os.path.exists(backup_path):
        raise HTTPException(404, f"Arquivo de backup não encontrado: {cfg.backup_file}")

    conn_cfg = cfg.connection
    try:
        if conn_cfg.engine == "mysql":
            conn = get_mysql_conn(conn_cfg)
            cur = conn.cursor()
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{cfg.database}`")
            cur.execute(f"USE `{cfg.database}`")
            with open(backup_path, "r", encoding="utf-8") as f:
                sql = f.read()
            # executa statement por statement
            statements = [s.strip() for s in sql.split(";") if s.strip() and not s.strip().startswith("--")]
            errors = []
            restored = 0
            for stmt in statements:
                try:
                    cur.execute(stmt)
                    restored += 1
                except Exception as e:
                    errors.append(str(e)[:100])
            conn.commit()
            conn.close()

        elif conn_cfg.engine == "postgresql":
            conn = get_pg_conn(conn_cfg)
            conn.autocommit = True
            cur = conn.cursor()
            with open(backup_path, "r", encoding="utf-8") as f:
                sql = f.read()
            statements = [s.strip() for s in sql.split(";") if s.strip() and not s.strip().startswith("--")]
            errors = []
            restored = 0
            for stmt in statements:
                try:
                    cur.execute(stmt)
                    restored += 1
                except Exception as e:
                    errors.append(str(e)[:100])
            conn.close()

        elif conn_cfg.engine == "mongodb":
            with open(backup_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            client = get_mongo_client(conn_cfg)
            db = client[cfg.database]
            restored = 0
            errors = []
            for col_name, docs in data.get("collections", {}).items():
                if cfg.tables and col_name not in cfg.tables:
                    continue
                if docs:
                    try:
                        db[col_name].delete_many({})
                        db[col_name].insert_many(docs)
                        restored += len(docs)
                    except Exception as e:
                        errors.append(str(e)[:100])
            client.close()

        elif conn_cfg.engine == "mssql":
            conn = get_mssql_conn(conn_cfg)
            cur = conn.cursor()
            with open(backup_path, "r", encoding="utf-8") as f:
                sql = f.read()
            statements = [s.strip() for s in sql.split(";") if s.strip() and not s.strip().startswith("--")]
            errors = []
            restored = 0
            for stmt in statements:
                try:
                    cur.execute(stmt)
                    restored += 1
                except Exception as e:
                    errors.append(str(e)[:100])
            conn.commit()
            conn.close()

        return {
            "success": True,
            "database": cfg.database,
            "statements_executed": restored,
            "errors": errors[:5],
            "backup_file": cfg.backup_file
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/backups")
def list_backups():
    """Lista todos os backups disponíveis."""
    files = []
    for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
        path = os.path.join(BACKUP_DIR, f)
        if os.path.isfile(path):
            stat = os.stat(path)
            files.append({
                "file": f,
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / 1024 / 1024, 2),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            })
    return {"backups": files}


@app.get("/api/backups/{filename}/download")
def download_backup(filename: str):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Arquivo não encontrado")
    return FileResponse(path, filename=filename, media_type="application/octet-stream")


@app.delete("/api/backups/{filename}")
def delete_backup(filename: str):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Arquivo não encontrado")
    os.remove(path)
    return {"success": True}


if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  DBMaster Suite - Backend API")
    print("  http://localhost:8000")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
