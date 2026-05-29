FROM python:3.11-slim

WORKDIR /app

# System deps (mysqldump, pg_dump, percona xtrabackup CLI tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-mysql-client \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p backups data

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
