"""Celery application: Redis broker, late acks, beat schedule.

Start:  ``celery -A app.workers.celery_app worker -l info``  /  ``celery -A app.workers.celery_app beat -l info``

Reliability: ``acks_late`` + ``reject_on_worker_lost`` mean a job whose worker died is redelivered; tasks are written to
be idempotent / to detect an abandoned "running" row (see services.discovery.execute_job).
"""
from __future__ import annotations

import importlib.util
import os
from typing import Any

from celery import Celery, signals
from celery.schedules import crontab

from app.core.config import get_settings

_settings = get_settings()


def _include() -> list[str]:
    mods = ["app.workers.tasks"]
    # the deployment worker module is owned by another stream; tolerate its absence so that the app still boots
    if importlib.util.find_spec("app.workers.deploy_tasks") is not None:
        mods.append("app.workers.deploy_tasks")
    return mods


celery_app = Celery("cdp", broker=_settings.redis_url, include=_include())
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=False,
    task_ignore_result=True,
    worker_prefetch_multiplier=1,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": 6 * 3600},   # > longest task (acks_late + redis redelivery)
    task_default_queue="celery",
    task_always_eager=os.environ.get("CDP_CELERY_EAGER", "").lower() in ("1", "true", "yes"),
    task_eager_propagates=False,
    beat_schedule={
        "discovery-schedule": {"task": "discovery.schedule_all", "schedule": crontab(minute="*/5")},
        "notifications-sweep": {"task": "notifications.sweep_pending", "schedule": crontab(minute="*/10")},
        "monitoring-check-expiry": {"task": "monitoring.check_expiry", "schedule": crontab(hour=6, minute=17)},
        "monitoring-verify-endpoints": {"task": "monitoring.verify_endpoints", "schedule": crontab(minute=41, hour="*/6")},
    },
)


@signals.setup_logging.connect
def _setup_logging(**_: Any) -> None:  # use our JSON/redacting logging instead of celery's formatter
    from app.core.logging import configure_logging

    configure_logging(_settings.log_level)


@signals.worker_process_init.connect
@signals.worker_ready.connect
def _apply_ssh_limits(**_: Any) -> None:       # K10: the per-host SSH limit setting must reach every worker
    from app.services import ssh_limits

    ssh_limits.apply_from_db()


def enqueue(task_name: str, *args: Any, countdown: float | None = None, **options: Any) -> None:
    """Send a task by name. Honors ``task_always_eager`` (tests): then it runs inline in this process."""
    if celery_app.conf.task_always_eager:
        celery_app.loader.import_default_modules()
        celery_app.tasks[task_name].apply(args=args)
        return
    celery_app.send_task(task_name, args=list(args), countdown=countdown, **options)
