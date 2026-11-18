"""Celery worker: runs scans off the API process.  celery -A vulnscan.worker worker"""
from __future__ import annotations

from celery import Celery

from .config import get_settings
from .db import Store
from .models import ScanRequest
from .pipeline import run_scan

settings = get_settings()
celery_app = Celery("vulnscan", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(task_acks_late=True, worker_prefetch_multiplier=1, task_track_started=True,
                       broker_connection_retry_on_startup=True, result_expires=86400)
app = celery_app


@celery_app.task(name="vulnscan.run_scan")
def run_scan_task(scan_id: str, request_json: str) -> dict:
    req = ScanRequest.model_validate_json(request_json)
    try:
        result = run_scan(scan_id, req, settings, Store(settings))
        return {"scan_id": scan_id, "summary": result["summary"]}
    except Exception as e:  # status already saved by the pipeline
        return {"scan_id": scan_id, "error": str(e)}
