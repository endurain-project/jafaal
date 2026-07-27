"""Auth-owned maintenance tasks, their schedule, and a runner for them.

JAFAAL accumulates rows that only a periodic sweep removes: consumed OAuth
states, rotated refresh tokens past their grace window, expired password-reset /
sign-up / IdP-link tokens, and idle sessions. Nothing in the request path deletes
them, so a deployment that never runs these grows those tables without bound —
which is a storage problem, a query-performance problem, and (for anything
holding token material) a data-retention problem.

Three ways to run them, in increasing order of host involvement:

1. :func:`start_background_scheduler` — a daemon thread that calls
   :func:`run_due_tasks` on a fixed tick. One line in an ASGI lifespan and the
   deployment is correct. Suitable when the app runs as a single process, or
   when running the sweep on every worker is acceptable (the deletes are
   idempotent and contend only briefly).
2. :func:`run_due_tasks` — call it from the scheduler you already run
   (APScheduler, Celery beat, a Kubernetes CronJob). It tracks each task's last
   run in-process and executes only those that are due, so the caller can invoke
   it on any cadence at or below :data:`SCHEDULER_TICK_SECONDS`.
3. The individual callables in :data:`MAINTENANCE_TASKS` (also re-exported at
   module level) — schedule each one yourself on its own cadence.

Every task is failure-isolated: a task that raises is logged and the cycle
continues, so one broken sweep cannot stop the others.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

import jafaal._internal.security_stores as jafaal_security_stores
from jafaal.identity_providers.link_tokens.utils import delete_idp_link_expired_tokens_from_db
from jafaal.oauth_state.utils import delete_expired_oauth_states_from_db
from jafaal.password_reset_tokens.utils import (
    delete_invalid_tokens_from_db as delete_invalid_password_reset_tokens_from_db,
)
from jafaal.sessions.rotated_refresh_tokens.utils import cleanup_expired_rotated_tokens
from jafaal.sessions.utils import cleanup_idle_sessions
from jafaal.sign_up_tokens.utils import (
    delete_invalid_tokens_from_db as delete_invalid_sign_up_tokens_from_db,
)

__all__ = [
    "MAINTENANCE_TASKS",
    "SCHEDULER_TICK_SECONDS",
    "MaintenanceTask",
    "cleanup_expired_pending_mfa_logins",
    "cleanup_expired_rotated_tokens",
    "cleanup_idle_sessions",
    "delete_expired_oauth_states_from_db",
    "delete_idp_link_expired_tokens_from_db",
    "delete_invalid_password_reset_tokens_from_db",
    "delete_invalid_sign_up_tokens_from_db",
    "is_scheduler_running",
    "run_due_tasks",
    "start_background_scheduler",
    "stop_background_scheduler",
]

logger = logging.getLogger(__name__)


def cleanup_expired_pending_mfa_logins() -> int:
    """Evict expired pending MFA login entries."""
    return jafaal_security_stores.cleanup_expired_pending_mfa_logins()


@dataclass(frozen=True)
class MaintenanceTask:
    """One recurring cleanup job, with the cadence JAFAAL recommends for it.

    Attributes:
        name: Stable identifier, used in logs and as the scheduling key.
        run: The callable to invoke. Takes no arguments and manages its own
            database session; the return value (a deleted-row count, where the
            task reports one) is returned by :func:`run_due_tasks`.
        interval_seconds: How often the task should run. Derived from what the
            task deletes: state with a short lifetime is swept often so it does
            not accumulate between runs, long-lived state less so.
        description: What the task removes, and why it matters.
    """

    name: str
    run: Callable[[], object]
    interval_seconds: int
    description: str


#: How often :func:`start_background_scheduler` wakes up to look for due tasks.
#: The finest schedulable granularity — no task is scheduled more often.
SCHEDULER_TICK_SECONDS: int = 60

#: Every recurring cleanup JAFAAL owns, with its recommended cadence.
MAINTENANCE_TASKS: tuple[MaintenanceTask, ...] = (
    MaintenanceTask(
        name="oauth_states",
        run=delete_expired_oauth_states_from_db,
        interval_seconds=300,
        description=(
            "Delete consumed/expired OAuth state rows. One is minted on every SSO login attempt and they "
            "live 10 minutes, so this is the fastest-growing JAFAAL table on an SSO-enabled deployment."
        ),
    ),
    MaintenanceTask(
        name="rotated_refresh_tokens",
        run=cleanup_expired_rotated_tokens,
        interval_seconds=600,
        description=(
            "Delete rotated refresh-token records past their reuse-detection window. One row is written "
            "per /auth/refresh call, so this grows with session count times refresh frequency. The rows "
            "hold encrypted replacement tokens, so sweeping them is a retention control, not just a size one."
        ),
    ),
    MaintenanceTask(
        name="pending_mfa_logins",
        run=cleanup_expired_pending_mfa_logins,
        interval_seconds=300,
        description=(
            "Evict expired pending-MFA tickets from the state store. A no-op on a backend with native "
            "expiry (Redis), but required for the in-memory store, which has no background expiry."
        ),
    ),
    MaintenanceTask(
        name="password_reset_tokens",
        run=delete_invalid_password_reset_tokens_from_db,
        interval_seconds=3600,
        description="Delete used and expired password-reset tokens.",
    ),
    MaintenanceTask(
        name="sign_up_tokens",
        run=delete_invalid_sign_up_tokens_from_db,
        interval_seconds=3600,
        description="Delete used and expired sign-up / email-verification tokens.",
    ),
    MaintenanceTask(
        name="idp_link_tokens",
        run=delete_idp_link_expired_tokens_from_db,
        interval_seconds=3600,
        description="Delete expired identity-provider account-link tokens.",
    ),
    MaintenanceTask(
        name="idle_sessions",
        run=cleanup_idle_sessions,
        interval_seconds=3600,
        description=(
            "Delete sessions idle beyond AuthSettings.session_idle_timeout_hours. A no-op unless "
            "session_idle_timeout_enabled is set; the per-request timeout check already refuses them, "
            "so this only reclaims the rows."
        ),
    ),
)

_last_run: dict[str, float] = {}
_state_lock = threading.Lock()
_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()


def _claim_due_tasks(now: float, tasks: tuple[MaintenanceTask, ...]) -> list[MaintenanceTask]:
    """Return the tasks whose interval has elapsed, marking them as run.

    Claiming under the lock (rather than after execution) means two concurrent
    callers cannot both pick up the same task, so a host may safely call
    :func:`run_due_tasks` from more than one thread or worker greenlet.
    """
    due: list[MaintenanceTask] = []
    with _state_lock:
        for task in tasks:
            last = _last_run.get(task.name)
            if last is None or (now - last) >= task.interval_seconds:
                _last_run[task.name] = now
                due.append(task)
    return due


def run_due_tasks(tasks: tuple[MaintenanceTask, ...] = MAINTENANCE_TASKS) -> dict[str, object]:
    """Run every task whose interval has elapsed, isolating failures.

    Safe to call on any cadence: due-ness is tracked per task, so calling this
    once a minute still runs the hourly sweeps only once an hour. Intended as the
    single entry point for a host's existing scheduler.

    On the first call every task is due, so a fresh process sweeps once at
    startup — which is what makes a short-lived worker (a CronJob pod) useful
    with no further wiring.

    Args:
        tasks: Tasks to consider. Defaults to :data:`MAINTENANCE_TASKS`.

    Returns:
        Mapping of the task names that ran to their result: a deleted-row count
        for the tasks that report one, ``None`` otherwise, or the exception
        instance when the task failed.
    """
    results: dict[str, object] = {}
    for task in _claim_due_tasks(time.monotonic(), tasks):
        try:
            results[task.name] = task.run()
        except Exception as err:
            # Isolated per task: one failing sweep must not stop the others, and
            # a maintenance failure must never take the process down.
            logger.error(f"Maintenance task {task.name!r} failed: {type(err).__name__}", exc_info=err)
            results[task.name] = err
    return results


def _scheduler_loop(tick_seconds: int, tasks: tuple[MaintenanceTask, ...]) -> None:
    """Body of the background scheduler thread: sweep now, then every tick."""
    logger.info(f"JAFAAL maintenance scheduler started ({len(tasks)} tasks, {tick_seconds}s tick)")
    run_due_tasks(tasks)
    while not _scheduler_stop.wait(tick_seconds):
        run_due_tasks(tasks)
    logger.info("JAFAAL maintenance scheduler stopped")


def start_background_scheduler(
    *,
    tick_seconds: int = SCHEDULER_TICK_SECONDS,
    tasks: tuple[MaintenanceTask, ...] = MAINTENANCE_TASKS,
) -> None:
    """Start a daemon thread that runs the maintenance tasks on a tick.

    The batteries-included option for a host without its own scheduler::

        @contextlib.asynccontextmanager
        async def lifespan(app: FastAPI):
            jafaal.maintenance.start_background_scheduler()
            yield
            await jafaal.shutdown()

    The thread is a daemon, so it never blocks interpreter exit; call
    :func:`stop_background_scheduler` (or :func:`jafaal.shutdown`) for an orderly
    stop. Calling this twice is a no-op — the existing thread keeps running.

    Requires the session factory to be installed
    (:func:`jafaal.configure_sessionmaker`), since the tasks open their own
    sessions.

    Args:
        tick_seconds: How often to look for due tasks.
        tasks: Tasks to run. Defaults to :data:`MAINTENANCE_TASKS`.
    """
    global _scheduler_thread
    with _state_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            logger.debug("JAFAAL maintenance scheduler is already running")
            return
        _scheduler_stop.clear()
        _scheduler_thread = threading.Thread(
            target=_scheduler_loop,
            args=(tick_seconds, tasks),
            name="jafaal-maintenance",
            daemon=True,
        )
        _scheduler_thread.start()


def stop_background_scheduler(timeout: float = 5.0) -> bool:
    """Signal the maintenance thread to stop and wait for it to finish.

    Args:
        timeout: Maximum seconds to wait for the thread to exit.

    Returns:
        ``True`` when the thread stopped (or was never running).
    """
    global _scheduler_thread
    with _state_lock:
        thread = _scheduler_thread
        _scheduler_thread = None
    if thread is None:
        return True
    _scheduler_stop.set()
    thread.join(timeout)
    return not thread.is_alive()


def is_scheduler_running() -> bool:
    """Return whether the background maintenance thread is alive."""
    with _state_lock:
        return _scheduler_thread is not None and _scheduler_thread.is_alive()
