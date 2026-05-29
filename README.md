# VaultDB Security Suite v2.0

> **Plataforma enterprise de Backup & Disaster Recovery — Application-Aware**
> PO: Natã (Coordenação de Infraestrutura)

---

## Visão Geral

O VaultDB é uma solução de classe corporativa para backup e DR de bancos de dados, com foco em **consistência transacional**, **RPO mínimo** e **segurança contra ransomware**. Opera no modelo Client-Server (Director + Agent).

## Código na raiz e em `vaultdb-security-suite/`

Neste workspace o mesmo conjunto de ficheiros pode existir na **raiz do projeto** (`server.py`, `index.html`, `docker-compose.yml`, `tasks.py`, `Dockerfile`, etc.) e dentro da pasta **`vaultdb-security-suite/`**. Tratam-se de **espelhos** da mesma aplicação: depois de editar num sítio, alinhe o outro (cópia ou merge) para evitar versões diferentes da API e do painel. **Exceção intencional:** o `docker-compose.yml` na **raiz** usa portas por defeito **8001 / 6380 / 9091** para conviver com outro VaultDB; na pasta **suite** mantêm-se **8000 / 6379 / 9090**. Ao correr **Docker Compose**, os volumes `./backups` e `./data` são relativos ao **diretório atual** do comando — use sempre a mesma pasta se quiser o mesmo histórico de backups e o mesmo `store.json`. Para assistentes de código, ver também **`AGENTS.md`**.

## Início Rápido

```bash
# 1. Instalar dependências
pip install fastapi uvicorn pymysql psycopg2-binary pymongo python-jose[cryptography] structlog prometheus-client

# 2. Iniciar o Director
python server.py

# 3. Acessar
http://localhost:8000
# Login: admin / vaultdb2024
# API Docs: http://localhost:8000/api/docs
```

## Deploy com Docker

Na **raiz** de `files (5)` (cópia paralela), as portas **por defeito** no `docker-compose.yml` são **8001** (API), **6380** (Redis no host) e **9091** (Prometheus), para poder subir **em paralelo** com outro VaultDB já em 8000/6379/9090. Painel: **http://localhost:8001**

Na pasta **`vaultdb-security-suite/`**, as predefinições são as clássicas **8000 / 6379 / 9090** (instalação única).

```bash
cp .env.example .env
# Edite .env (SECRET_KEY, Redis se necessário, MYSQLDUMP_SSL_MODE, Telegram, etc.)

docker compose up -d --build
```

- **Director (raiz files 5):** http://localhost:8001 — na suite: http://localhost:8000  
- **API docs:** mesma porta do Director + `/api/docs`  
- **Prometheus:** http://localhost:9091 na raiz; http://localhost:9090 na suite  
- **Redis no host (raiz):** `localhost:6380` — na suite: `localhost:6379` (ou defina `HOST_PORT_REDIS` no `.env`).
- **Login:** `admin` / `vaultdb2024` (até alterar no `store.json`).
- O worker Celery regista as tasks com `-I tasks`; `MYSQLDUMP_SSL_MODE` e `MYSQLDUMP_EXTRA_ARGS` vêm do `.env` (substituição no `docker-compose.yml`, predefinição `DISABLED` para MariaDB 11).

Para reconstruir só a imagem após mudanças no código: `docker compose build --no-cache && docker compose up -d`.

**Dois stacks ao mesmo tempo:** na **raiz de `files (5)`** as portas por defeito já estão deslocadas (8001 / 6380 / 9091). Na pasta **`vaultdb-security-suite/`** use `docker compose down` antes de subir outra cópia nas mesmas portas clássicas, ou defina `HOST_PORT_*` no `.env`. O comando para parar um projeto é `docker compose down` (sem `-d`).

## Preparar um Linux para restore (MySQL/MariaDB)

Na página **Disaster Recovery → Preparar Linux**, use **“Baixar script .sh”**. O script (Ubuntu/Debian + `sudo`):

- Instala `mariadb-server` ou `default-mysql-server` conforme a versão detetada no backup (metadados `.meta.json` ou cabeçalho do `.sql`).
- Cria o banco (`CREATE DATABASE IF NOT EXISTS`) e o utilizador com as **mesmas credenciais** da conexão VaultDB escolhida, com `GRANT ALL` nesse banco.
- A API é `POST /api/linux-prepare/script` (módulo separado do fluxo de restore).

Para **alinhar a versão byte-a-byte** com o servidor de origem, pode ser necessário configurar os repositórios oficiais Oracle ou MariaDB no Linux (o script usa os pacotes padrão da distribuição).

## Executáveis desktop (Linux / Windows .exe / macOS)

Para uma instalação local sem Docker, o projeto pode ser empacotado num **executável único**
(painel + API), que arranca o servidor e abre o navegador. Corre em **modo síncrono** (sem Celery/Redis).

```bash
# Windows (PowerShell, a partir da raiz)
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1   # → dist\VaultDB.exe

# macOS (a partir da raiz)
bash packaging/build_macos.sh                                          # → dist/VaultDB

# Linux (a partir da raiz)
bash packaging/build_linux.sh                                          # → dist/VaultDB
```

Dados persistentes ficam em `vaultdb-data/` junto ao executável (ou `VAULTDB_HOME`).
Detalhes em [`packaging/README.md`](packaging/README.md).

**Builds automáticos:** ao criar uma tag `v*` (`git tag v2.2.0 && git push origin v2.2.0`), o workflow
`.github/workflows/release.yml` publica numa **GitHub Release** os executáveis do painel para
**Linux x64**, **Windows x64** (`VaultDB.exe`) e **macOS** (arm64/x64), além dos binários do
**agente Go** (Linux/macOS/Windows, amd64/arm64).

## Arquitetura

```
vaultdb/
├── server.py          ← Director API (FastAPI) — BACKEND PRINCIPAL
├── index.html         ← Dashboard SPA — FRONTEND COMPLETO
├── tasks.py           ← Celery tasks (backup assíncrono)
├── requirements.txt   ← Dependências Python
├── docker-compose.yml ← Stack completa (API + Worker + Scheduler + Redis + Prometheus)
├── Dockerfile
├── .env.example       ← Template de configuração
├── monitoring/
│   └── prometheus.yml ← Scraping config
├── backups/           ← Arquivos de backup (gitignored)
└── data/              ← Store da aplicação (gitignored)
```

## Funcionalidades

### Director (Painel Web)
| Módulo | Descrição |
|---|---|
| Dashboard | Métricas em tempo real, conexões, backups recentes, auditoria |
| Servidores | Gerenciar conexões MySQL/PostgreSQL/MongoDB/SQL Server |
| Novo Backup | Full ou por tabelas, compressão Zstandard/GZIP, throttle I/O |
| Meus Backups | Lista com download, restore rápido, exclusão |
| Agendamentos | CRON personalizado, GFS, retenção configurável, alertas Telegram |
| Restaurar | **Workflow de aprovação obrigatório** (e-mail SMTP ou botão/página de confirmação) — LGPD/Compliance |
| Preparar Linux (DR) | Gera script `.sh` que instala MariaDB/MySQL, cria banco e utilizador alinhados ao backup |
| Diagrama ER | Visualização interativa FK via INFORMATION_SCHEMA |
| Monitoramento | Prometheus, Telegram, Proxmox Sandbox, S3/Parquet |
| Configurações (admin) | SMTP, Telegram e gestão de utilizadores (criar/remover/senha) persistidos no store |
| Auditoria | Trilha imutável com níveis de risco (low/medium/high/critical) |

### API B2B (JWT)
```bash
# Obter token
curl -X POST http://localhost:8000/api/auth/token/json \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"vaultdb2024"}'

# Disparar backup (integração ERP/B2B)
curl -X POST http://localhost:8000/api/backups/trigger \
  -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "connection_id": "ID_DA_CONEXAO",
    "database": "meu_banco",
    "backup_type": "full",
    "compression": "zstd"
  }'
```

## Segurança (Zero Trust)

- ❌ `shell=True` **nunca utilizado** — argumentos sempre em listas isoladas
- ❌ Senhas **nunca em arquivos de configuração** — enviadas criptografadas em runtime
- ✅ **Workflow de aprovação** obrigatório para qualquer restore
- ✅ **Trilha de auditoria** imutável com níveis de risco
- ✅ **JWT** para autenticação da API B2B
- ✅ Arquivo `.cnf` temporário para `mysqldump` (não expõe senha no process list)

## Integrações

| Integração | Status | Configuração |
|---|---|---|
| Prometheus + Grafana | ✅ Ativo | `GET /metrics` |
| Telegram Alerts | ⚙ Config | `TELEGRAM_TOKEN` no `.env` |
| AWS S3 / Parquet | ⚙ Config | `AWS_*` no `.env` |
| Proxmox Sandbox | ⚙ Config | `PROXMOX_HOST` no `.env` |
| Celery (async) | ✅ Ativo | `redis` + `celery -A server worker` |

## Endpoints da API

```
POST /api/auth/token             → JWT login
POST /api/auth/token/json        → JWT login (JSON body)
GET  /api/connections            → listar conexões
POST /api/connections            → criar conexão
POST /api/connections/test       → testar conexão
GET  /api/connections/{id}/tables/{db}  → listar tabelas
POST /api/backups/trigger        → disparar backup
GET  /api/backups                → listar backups
GET  /api/backups/{file}/download → download
DELETE /api/backups/{file}       → deletar
POST /api/restore/request        → solicitar restore (PENDENTE)
GET  /api/restore/confirm?token= → página HTML de confirmação (abrir link no browser, sem 405)
POST /api/restore/approve-submit → aprovar via formulário (token no corpo)
POST /api/restore/approve/{token} → aprovar (JSON, usado pelo painel)
GET  /api/restore/requests       → listar solicitações
POST /api/linux-prepare/script   → gerar script .sh de preparação Linux (DR)
GET  /api/schedules              → listar agendamentos
POST /api/schedules              → criar agendamento
DELETE /api/schedules/{id}       → remover agendamento
GET  /api/er-diagram/{id}/{db}   → diagrama ER (FKs)
GET  /api/audit                  → trilha de auditoria
GET  /api/settings               → ler SMTP/Telegram (admin)
PUT  /api/settings               → gravar SMTP/Telegram (admin)
POST /api/settings/test-smtp     → enviar e-mail de teste (admin)
GET  /api/users                  → listar utilizadores (admin)
POST /api/users                  → criar utilizador (admin)
DELETE /api/users/{username}     → remover utilizador (admin)
POST /api/users/{username}/password → alterar palavra-passe (admin)
GET  /api/tenants                → listar tenants (admin)
POST /api/tenants                → criar tenant (admin)
DELETE /api/tenants/{id}         → remover tenant (admin)
POST /api/export/parquet         → exportar tabelas para Parquet (+ S3 opcional)
POST /api/backups/xtrabackup     → backup físico full/incremental (XtraBackup)
GET  /api/backups/xtrabackup/script → script XtraBackup p/ host da BD
POST /api/sandbox/proxmox        → criar LXC e validar restauro isolado
DELETE /api/sandbox/proxmox/{vmid} → destruir sandbox
POST /api/alerts/test            → testar alertas
GET  /api/stats                  → estatísticas gerais
GET  /metrics                    → Prometheus metrics
GET  /api/docs                   → Swagger UI
```

## Engines Suportadas

| Engine | Driver | Backup Nativo | Fallback Python |
|---|---|---|---|
| MySQL / MariaDB | pymysql | mysqldump + Percona XtraBackup | ✅ |
| PostgreSQL | psycopg2-binary | pg_dump | ✅ |
| MongoDB | pymongo | — | ✅ (JSON) |
| SQL Server | pyodbc | — | ✅ |

## Roadmap (Próximas versões)

- [x] Agente Go (binário único, systemd) — ver `agent/`
- [x] Backup incremental via Percona XtraBackup (`POST /api/backups/xtrabackup`)
- [x] Mascaramento LGPD automático no restore (`mask_lgpd`)
- [x] Sandbox Proxmox LXC automatizado (`POST /api/sandbox/proxmox`)
- [x] Exportação Parquet para AWS S3 (`POST /api/export/parquet`)
- [x] Interface de aprovação de restore por e-mail (template HTML)
- [x] Página de confirmação de restore no browser (sem erro 405)
- [x] Multi-tenant com papéis (admin/viewer) e gestão na UI
- [x] Configuração de SMTP/Telegram/Proxmox pelo painel
- [ ] Mascaramento LGPD com regras personalizáveis por coluna (UI)
- [ ] Migração do `store.json` para base de dados (SQLAlchemy)

## Histórico de alterações recentes

### v2.2 — novos módulos
- **Agente Go (`agent/`):** binário único e estático (sem CGO) que dispara backups via Director API em intervalo configurável; inclui unit `systemd`, `Makefile` e `.env`. CI valida `go vet` + `go build`.
- **XtraBackup incremental:** `POST /api/backups/xtrabackup` (full/incremental com encadeamento por LSN quando o binário existe no host) e `GET /api/backups/xtrabackup/script` (script `full|incremental|prepare|restore` para correr no host da BD).
- **Mascaramento LGPD:** quando `mask_lgpd=true` no pedido de restore, colunas sensíveis (e-mail, nome, CPF/CNPJ/RG, telefone, endereço, datas de nascimento, segredos) são anonimizadas deterministicamente (MD5) após o restauro, sem tocar em chaves primárias.
- **Sandbox Proxmox:** `POST /api/sandbox/proxmox` cria um LXC isolado (API Proxmox via token) e devolve um script `pct exec` para instalar a BD, restaurar e validar; `DELETE /api/sandbox/proxmox/{vmid}` destrói.
- **Exportação Parquet/S3:** `POST /api/export/parquet` (pyarrow) com upload opcional para AWS S3 (boto3); também acionável no backup via `export_parquet`.
- **Multi-tenant:** `tenants` no store, `tenant_id` em conexões/utilizadores, scoping automático de conexões e ações; gestão de tenants e Proxmox no menu **Configurações**.
- **E-mail de aprovação:** agora em HTML responsivo (multipart texto+HTML).

### v2.1

- **Restore MySQL robusto:** aplicação do dump via cliente `mysql`/`mariadb` em streaming; trata a linha *sandbox* do MariaDB, `LOCK TABLES` e o par `AUTOCOMMIT`. Fallback PyMySQL passa a ignorar `SET … AUTOCOMMIT`, corrigindo o erro **1231** (`autocommit can't be set to the value of 'NULL'`).
- **Aprovação de restore:** `GET /api/restore/confirm?token=` mostra página de confirmação (resolve o **405** ao abrir o link no browser); `POST /api/restore/approve-submit` para o formulário; botão «Aprovar» no painel via JSON.
- **Módulo Configurações (admin):** SMTP, Telegram e utilizadores persistidos em `data/store.json`.
- **Módulo DR «Preparar Linux»** separado do fluxo de restore (`POST /api/linux-prepare/script`).
- **Docker:** sem `container_name` fixo; na raiz de `files (5)` as portas por defeito são **8001 / 6380 / 9091** (paralelo com outro VaultDB), na pasta `vaultdb-security-suite/` mantêm-se **8000 / 6379 / 9090**.

---

*VaultDB Security Suite — Desenvolvido sob supervisão de Natã (Coordenação de Infraestrutura)*
