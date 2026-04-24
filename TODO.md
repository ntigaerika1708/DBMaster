# Plano de Fixes - DBMaster Suite

## Passos em execução

### 1. [x] Revisar código e identificar problemas
- server.py: `uvicorn.run` duplicado, senha exposta no process list, dead code
- index.html: ID incorreto `sf-label` vs `sf-storage`, lógica de tamanho inconsistente
- requirements.txt: faltando pyodbc

### 2. Corrigir server.py
- [x] Remover uvicorn.run duplicado
- [x] Trocar `-pSENHA` por `--defaults-extra-file` (segurança)
- [x] Remover variável `tables_arg` sem uso

### 3. Corrigir index.html
- [x] Criar helper `formatSize` unificado
- [x] Aplicar em `updateDashMetrics` e `updateBackupCount`
- [x] Corrigir ID `sf-label` → `sf-storage`

### 4. Atualizar requirements.txt
- [x] Adicionar pyodbc (opcional SQL Server)

### 5. Garantir estrutura
- [x] Criar `backups/.gitkeep`

### 6. Testar
- [x] Subir servidor e validar inicialização

