"""
VaultDB Security Suite — Celery Tasks
Tasks assíncronas para execução de backup, restore e validação sandbox.
"""
import json
import os
from datetime import datetime

try:
    from celery import Celery
    from server import (
        celery_app, BACKUP_DIR,
        ConnectionConfig, BackupTrigger,
        _run_backup_sync, _run_restore_sync,
        backup_total, backup_size_bytes,
        _send_telegram, audit_log
    )
    CELERY_OK = True
except ImportError:
    CELERY_OK = False


if CELERY_OK:
    @celery_app.task(name="vaultdb.tasks.run_backup", bind=True, max_retries=2, default_retry_delay=60)
    def run_backup_task(self, cfg_dict: dict, conn_dict: dict):
        """Executa backup em background via Celery."""
        cfg = BackupTrigger(**cfg_dict)
        conn = ConnectionConfig(**conn_dict)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = cfg.output_name or f"{cfg.database}_{ts}"
        try:
            result = _run_backup_sync(conn, cfg, name, ts)
            backup_total.labels(engine=conn.engine, status="success").inc()
            backup_size_bytes.observe(result.get("size_bytes", 0))
            try:
                _send_telegram(
                    f"✅ Backup concluído\n"
                    f"Banco: `{cfg.database}`\n"
                    f"Arquivo: `{result['file']}`\n"
                    f"Tamanho: {result['size_mb']} MB"
                )
            except Exception:
                pass
            return result
        except Exception as exc:
            backup_total.labels(engine=conn.engine, status="failure").inc()
            try:
                _send_telegram(
                    f"❌ Backup FALHOU\n"
                    f"Banco: `{cfg.database}`\n"
                    f"Erro: {str(exc)[:200]}"
                )
            except Exception:
                pass
            raise self.retry(exc=exc)

    @celery_app.task(name="vaultdb.tasks.scheduled_backup")
    def scheduled_backup_task(schedule_id: str):
        """Executado pelo Celery Beat para agendamentos."""
        from server import load_store, save_store
        store = load_store()
        sched = store["schedules"].get(schedule_id)
        if not sched or not sched.get("enabled"):
            return {"skipped": True}
        conn_data = store["connections"].get(sched["connection_id"])
        if not conn_data:
            return {"error": "Connection not found"}
        conn = ConnectionConfig(**conn_data)
        cfg = BackupTrigger(
            connection_id=sched["connection_id"],
            database=sched["database"],
            backup_type=sched.get("backup_type", "full"),
            compression=sched.get("compression", "zstd"),
        )
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"{sched['database']}_{sched['backup_type']}_{ts}"
        result = _run_backup_sync(conn, cfg, name, ts)
        store = load_store()
        store["schedules"][schedule_id]["last_run"] = datetime.now().isoformat()
        store["schedules"][schedule_id]["runs_total"] = store["schedules"][schedule_id].get("runs_total", 0) + 1
        store["schedules"][schedule_id]["runs_success"] = store["schedules"][schedule_id].get("runs_success", 0) + 1
        save_store(store)
        return result

    @celery_app.task(name="vaultdb.tasks.validate_backup_sandbox")
    def validate_backup_sandbox_task(backup_file: str, proxmox_host: str, proxmox_token: str):
        """
        Sobe container efêmero no Proxmox, restaura backup,
        roda mysqlcheck e emite laudo.
        """
        import httpx
        # 1. Criar container LXC via API Proxmox
        # 2. Instalar MySQL no container
        # 3. Restaurar backup
        # 4. Rodar mysqlcheck
        # 5. Emitir laudo
        # 6. Destruir container
        # Implementação completa requer Proxmox API token
        return {
            "sandbox": "not_implemented",
            "note": "Configure PROXMOX_HOST e PROXMOX_TOKEN no .env"
        }
