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
| Restaurar | **Workflow de aprovação obrigatório via e-mail** (LGPD/Compliance) |
| Diagrama ER | Visualização interativa FK via INFORMATION_SCHEMA |
| Monitoramento | Prometheus, Telegram, Proxmox Sandbox, S3/Parquet |
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
POST /api/restore/approve/{token} → aprovar via e-mail
GET  /api/restore/requests       → listar solicitações
GET  /api/schedules              → listar agendamentos
POST /api/schedules              → criar agendamento
DELETE /api/schedules/{id}       → remover agendamento
GET  /api/er-diagram/{id}/{db}   → diagrama ER (FKs)
GET  /api/audit                  → trilha de auditoria
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

- [ ] Agente Go (binário único, systemd)
- [ ] Backup incremental via Percona XtraBackup
- [ ] Mascaramento LGPD automático no restore
- [ ] Sandbox Proxmox LXC automatizado
- [ ] Exportação Parquet para AWS S3
- [ ] Interface de aprovação de restore por e-mail (template HTML)
- [ ] Multi-tenant (múltiplos usuários e permissões)

---

*VaultDB Security Suite — Desenvolvido sob supervisão de Natã (Coordenação de Infraestrutura)*
