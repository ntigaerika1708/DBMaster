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

## Próximos passos
- [ ] Validar restore ponta-a-ponta contra MySQL real e registar evidência
- [ ] Template HTML para e-mail de aprovação
- [ ] Mascaramento LGPD automático no restore
- [ ] Backup incremental (Percona XtraBackup)
- [ ] Mover store JSON para base de dados real (SQLAlchemy) em produção
