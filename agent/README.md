# VaultDB Agent (Go)

Binário único e estático para correr nos hosts e disparar backups no **Director API** do VaultDB
de forma agendada, integrando-se ao `systemd`. Sem dependências externas (apenas a stdlib do Go).

## Compilar

```bash
cd agent
make build                 # gera ./vaultdb-agent (binário estático)
# ou multi-plataforma:
make build-all             # dist/vaultdb-agent-linux-amd64, -arm64
```

Requer Go 1.22+. Sem CGO (`CGO_ENABLED=0`), o binário é portátil entre distribuições Linux.

## Instalar como serviço (systemd)

```bash
sudo make install                       # copia binário, unit e .env de exemplo
sudoedit /etc/vaultdb-agent.env         # preencher director, credenciais, conn, db
sudo systemctl enable --now vaultdb-agent
journalctl -u vaultdb-agent -f          # acompanhar
```

## Uso manual

```bash
# Daemon (primeira execução imediata, depois a cada 24h)
./vaultdb-agent -director http://director:8000 -user admin -pass *** \
  -conn <connection_id> -db meu_banco -interval 24h

# Um único backup e termina (útil em cron/CI)
./vaultdb-agent -conn <id> -db meu_banco -once

# Com JWT já obtido (sem expor a senha)
VAULTDB_TOKEN=eyJ... ./vaultdb-agent -conn <id> -db meu_banco -once
```

## Flags / variáveis de ambiente

| Flag | Env | Descrição |
|---|---|---|
| `-director` | `VAULTDB_DIRECTOR` | URL do Director API |
| `-user` / `-pass` | `VAULTDB_USER` / `VAULTDB_PASS` | login JWT |
| `-token` | `VAULTDB_TOKEN` | JWT pré-obtido (alternativa a user/pass) |
| `-conn` | `VAULTDB_CONN` | `connection_id` alvo |
| `-db` | `VAULTDB_DB` | base de dados |
| `-type` | `VAULTDB_TYPE` | `full` \| `incremental` |
| `-compression` | `VAULTDB_COMPRESSION` | `zstd` \| `gzip` \| `none` |
| `-tables` | `VAULTDB_TABLES` | lista separada por vírgula (vazio = todas) |
| `-interval` | `VAULTDB_INTERVAL` | intervalo (`6h`, `30m`, ...) |
| `-once` | — | executa uma vez e sai |
| `-version` | — | mostra versão |

O agente reautentica automaticamente se o token expirar (HTTP 401).
