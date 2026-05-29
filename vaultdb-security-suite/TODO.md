# Plano de Fixes & Evolução — VaultDB Security Suite

## Concluído (DBMaster → VaultDB)

### Backend / correções iniciais
- [x] Remover `uvicorn.run` duplicado
- [x] `mysqldump` com `--defaults-extra-file` (não expõe senha no process list)
- [x] Remover dead code (`tables_arg`, etc.)
- [x] `requirements.txt` com `pyodbc` (opcional SQL Server)
- [x] `backups/.gitkeep`

### Frontend
- [x] Helper `formatSize` unificado
- [x] Correção de IDs de storage no dashboard

## VaultDB Security Suite — entregue

### Restore
- [x] Restore MySQL via cliente `mysql`/`mariadb` em streaming
- [x] Tratamento de sandbox MariaDB, `LOCK TABLES` e par `AUTOCOMMIT`
- [x] Fallback PyMySQL ignora `SET … AUTOCOMMIT` (corrige erro 1231)
- [x] `GET /api/restore/confirm?token=` (página de confirmação, sem 405)
- [x] `POST /api/restore/approve-submit` (formulário) + botão «Aprovar» no painel (JSON)

### Configurações (admin)
- [x] SMTP (host/porta/utilizador/senha) com envio real e teste
- [x] Telegram (token/chat) gravado no store
- [x] Gestão de utilizadores: criar, remover, alterar senha, papéis admin/viewer

### Disaster Recovery
- [x] Módulo «Preparar Linux» (`POST /api/linux-prepare/script`) separado do restore

### Infra / Docker / Git
- [x] Compose sem `container_name` fixo; portas configuráveis (`HOST_PORT_*`)
- [x] Raiz `files (5)` em 8001/6380/9091; suite em 8000/6379/9090
- [x] `.gitignore` protege `.env`, dumps `.sql`, `data/` e arquivos comprimidos
- [x] Projeto publicado no GitHub (DBMaster) e CI de verificação

## v2.2 — novos módulos (entregue)
- [x] Template HTML para e-mail de aprovação (multipart texto+HTML)
- [x] Mascaramento LGPD automático no restore (`mask_lgpd`, anonimização MD5)
- [x] Exportação Parquet + upload AWS S3 (`POST /api/export/parquet`)
- [x] Multi-tenant: `tenant_id` em conexões/utilizadores, scoping e gestão na UI
- [x] Backup incremental via Percona XtraBackup (`/api/backups/xtrabackup` + script)
- [x] Sandbox Proxmox LXC automatizado (`/api/sandbox/proxmox`)
- [x] Agente Go (`agent/`): binário único + unit systemd + Makefile, validado no CI

## Distribuição (entregue)
- [x] Workflow de GitHub Releases para o agente Go (Linux/macOS/Windows, amd64/arm64)
- [x] Empacotamento desktop do projeto inteiro em executável Linux, Windows (`VaultDB.exe`) e macOS (`VaultDB`) via PyInstaller
- [x] `server.py` frozen-aware (recursos no bundle; dados em `vaultdb-data/` ou `VAULTDB_HOME`)
- [x] Build automático dos executáveis no CI ao criar tag `v*`
- [x] Instalador MSI (WiX) no Windows e AppImage no Linux; DMG no macOS
- [x] Assinatura/notarização opcional (Authenticode/Apple) ativada por secrets

## Próximos passos
- [ ] Validar restore e XtraBackup ponta-a-ponta contra MySQL/MariaDB real
- [ ] Fornecer certificados (secrets) para assinar/notarizar e remover avisos de Gatekeeper/SmartScreen
- [ ] Regras de mascaramento LGPD personalizáveis por coluna (UI)
- [ ] Automatizar o `pct exec` do sandbox (SSH ao host Proxmox) end-to-end
- [ ] Publicar binários do agente Go em GitHub Releases (CI)
- [ ] Mover store JSON para base de dados real (SQLAlchemy) em produção
