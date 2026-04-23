# DBMaster Suite — Instalação e Uso

## Pré-requisitos
- Python 3.10+
- pip

## Instalação rápida

```bash
# 1. Instale as dependências
pip install -r requirements.txt

# Para SQL Server (opcional), instale também:
pip install pyodbc

# 2. Inicie o servidor
python server.py

# 3. Acesse no navegador
http://localhost:8000
```

## Estrutura de arquivos

```
dbmaster/
├── server.py        ← Backend FastAPI (API + serve o HTML)
├── index.html       ← Frontend completo
├── requirements.txt ← Dependências Python
└── backups/         ← Diretório criado automaticamente para os backups
```

## Funcionalidades

### Conexões
- Suporta MySQL/MariaDB, PostgreSQL, SQL Server, MongoDB
- Teste de conexão em tempo real com latência e versão
- Salva conexões no localStorage do navegador

### Backup
- Backup full (banco inteiro) ou de tabelas específicas
- Usa mysqldump/pg_dump se disponível, senão fallback Python puro
- Arquivos salvos em `backups/` com timestamp
- Download do arquivo via botão

### Restore
- Restore completo ou de tabelas específicas
- Cria o banco de destino automaticamente se não existir
- Log de execução em tempo real
- Funciona com qualquer backup gerado pelo DBMaster

## Engines suportadas

| Engine       | Driver Python   | Ferramenta nativa |
|--------------|-----------------|-------------------|
| MySQL        | pymysql         | mysqldump         |
| PostgreSQL   | psycopg2-binary | pg_dump           |
| MongoDB      | pymongo         | —                 |
| SQL Server   | pyodbc          | —                 |

## API Endpoints

```
POST /api/test-connection   → Testa conexão
POST /api/list-tables       → Lista tabelas de um banco
POST /api/backup            → Executa backup
POST /api/restore           → Executa restore
GET  /api/backups           → Lista backups disponíveis
GET  /api/backups/{file}/download → Download de backup
DELETE /api/backups/{file}  → Remove backup
```

## Exemplo de uso via curl

```bash
# Testar conexão MySQL
curl -X POST http://localhost:8000/api/test-connection \
  -H "Content-Type: application/json" \
  -d '{"engine":"mysql","host":"127.0.0.1","port":3306,"user":"root","password":"senha","database":null}'

# Fazer backup
curl -X POST http://localhost:8000/api/backup \
  -H "Content-Type: application/json" \
  -d '{"connection":{"engine":"mysql","host":"127.0.0.1","port":3306,"user":"root","password":"senha"},"database":"meu_banco"}'
```
