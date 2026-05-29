# Notas para agentes (Cursor / IA)

## Código espelhado (raiz vs `vaultdb-security-suite/`)

Neste workspace a **raiz** e a pasta **`vaultdb-security-suite/`** podem conter o mesmo conjunto de ficheiros da aplicação (`server.py`, `index.html`, `docker-compose.yml`, `tasks.py`, `Dockerfile`, etc.). Depois de alterar um lado, **alinhe o outro** (cópia ou merge) para evitar divergência entre API, UI e stack Docker.

Documentação mais completa: secção **«Código na raiz e em `vaultdb-security-suite/`»** no `README.md`.

## Docker Compose

Os volumes `./backups` e `./data` são **relativos ao diretório atual** ao correr `docker compose`. Use sempre a mesma pasta de trabalho se precisar do mesmo histórico de backups e do mesmo `store.json`.

**Portas:** na **raiz** de `files (5)` o `docker-compose.yml` usa por defeito **8001 / 6380 / 9091** (API / Redis no host / Prometheus) para não colidir com outro VaultDB em 8000/6379/9090. Na pasta **`vaultdb-security-suite/`** as predefinições são **8000 / 6379 / 9090**. O painel na raiz: `http://localhost:8001`.
