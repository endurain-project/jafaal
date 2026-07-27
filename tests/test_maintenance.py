"""Tests for the maintenance task catalog, due-task runner, and scheduler."""

import threading
import time

import pytest

import jafaal.maintenance as maintenance


@pytest.fixture(autouse=True)
def _isolated_schedule():
    """Reset the module-level last-run bookkeeping between tests."""
    maintenance._last_run.clear()
    yield
    maintenance.stop_background_scheduler()
    maintenance._last_run.clear()


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #


def test_every_task_callable_runs_on_an_empty_db():
    # Each opens its own session_scope; with empty tables they are no-ops and
    # must not raise.
    for task in maintenance.MAINTENANCE_TASKS:
        assert callable(task.run)
        task.run()


def test_task_names_are_unique_and_intervals_are_schedulable():
    names = [task.name for task in maintenance.MAINTENANCE_TASKS]
    assert len(names) == len(set(names))
    for task in maintenance.MAINTENANCE_TASKS:
        # Nothing may be scheduled finer than the scheduler's own tick, or the
        # background loop would silently under-run it.
        assert task.interval_seconds >= maintenance.SCHEDULER_TICK_SECONDS
        assert task.description


def test_module_reexports_stay_in_sync_with_the_catalog():
    """The convenience re-exports must be the same callables the catalog runs.

    They are a documented surface for hosts that schedule each sweep
    individually; if the catalog drifts from them, one of the two is silently
    not being run in some deployment.
    """
    exported = {getattr(maintenance, name) for name in maintenance.__all__ if callable(getattr(maintenance, name))}
    for task in maintenance.MAINTENANCE_TASKS:
        assert task.run in exported


# --------------------------------------------------------------------------- #
# run_due_tasks
# --------------------------------------------------------------------------- #


def _task(name: str, interval: int, calls: list[str], result: object = None) -> maintenance.MaintenanceTask:
    def run() -> object:
        calls.append(name)
        if isinstance(result, Exception):
            raise result
        return result

    return maintenance.MaintenanceTask(name=name, run=run, interval_seconds=interval, description=name)


def test_first_call_runs_everything_then_respects_the_interval():
    calls: list[str] = []
    tasks = (_task("fast", 60, calls, result=3),)

    first = maintenance.run_due_tasks(tasks)
    assert first == {"fast": 3}
    assert calls == ["fast"]

    # Not due yet: a second immediate call must not re-run it.
    assert maintenance.run_due_tasks(tasks) == {}
    assert calls == ["fast"]


def test_a_failing_task_is_isolated_and_does_not_stop_the_cycle():
    calls: list[str] = []
    boom = RuntimeError("sweep exploded")
    tasks = (
        _task("first", 60, calls, result=boom),
        _task("second", 60, calls, result=1),
    )

    results = maintenance.run_due_tasks(tasks)

    assert calls == ["first", "second"]
    assert results["first"] is boom
    assert results["second"] == 1


def test_concurrent_runners_never_double_execute_a_task():
    """Two schedulers (or two workers) must not both claim the same due task.

    Due-ness is claimed under a lock *before* the task runs, so exactly one
    caller executes it however many race for it.
    """
    calls: list[str] = []
    calls_lock = threading.Lock()

    def run() -> None:
        with calls_lock:
            calls.append("x")

    tasks = (maintenance.MaintenanceTask(name="once", run=run, interval_seconds=3600, description="once"),)

    start = threading.Barrier(8)

    def worker() -> None:
        start.wait()
        maintenance.run_due_tasks(tasks)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert calls == ["x"]


def test_due_tasks_are_claimed_again_once_the_interval_elapses(monkeypatch):
    calls: list[str] = []
    tasks = (_task("periodic", 60, calls),)

    clock = [1_000.0]
    monkeypatch.setattr(maintenance.time, "monotonic", lambda: clock[0])

    maintenance.run_due_tasks(tasks)
    assert calls == ["periodic"]

    clock[0] += 59.0
    assert maintenance.run_due_tasks(tasks) == {}
    assert calls == ["periodic"]

    clock[0] += 1.0
    assert maintenance.run_due_tasks(tasks) == {"periodic": None}
    assert calls == ["periodic", "periodic"]


# --------------------------------------------------------------------------- #
# Background scheduler
# --------------------------------------------------------------------------- #


def test_background_scheduler_sweeps_immediately_and_stops_cleanly():
    ran = threading.Event()

    tasks = (
        maintenance.MaintenanceTask(
            name="immediate",
            run=ran.set,
            interval_seconds=3600,
            description="immediate",
        ),
    )

    maintenance.start_background_scheduler(tick_seconds=3600, tasks=tasks)
    try:
        # The loop sweeps once before its first wait, so a fresh process is
        # swept at startup rather than one tick later.
        assert ran.wait(5.0), "scheduler did not run the initial sweep"
        assert maintenance.is_scheduler_running()
    finally:
        assert maintenance.stop_background_scheduler(timeout=5.0)

    assert not maintenance.is_scheduler_running()


def test_starting_twice_does_not_spawn_a_second_thread():
    tasks = (maintenance.MaintenanceTask(name="noop", run=lambda: None, interval_seconds=3600, description="noop"),)

    maintenance.start_background_scheduler(tick_seconds=3600, tasks=tasks)
    first = maintenance._scheduler_thread
    maintenance.start_background_scheduler(tick_seconds=3600, tasks=tasks)
    try:
        assert maintenance._scheduler_thread is first
    finally:
        maintenance.stop_background_scheduler()


def test_stop_is_idempotent_when_never_started():
    assert maintenance.stop_background_scheduler() is True


def test_scheduler_survives_a_task_that_always_raises():
    attempts: list[float] = []

    def always_fails() -> None:
        attempts.append(time.monotonic())
        raise RuntimeError("nope")

    tasks = (
        maintenance.MaintenanceTask(
            name="broken",
            run=always_fails,
            interval_seconds=0,
            description="broken",
        ),
    )

    maintenance.start_background_scheduler(tick_seconds=1, tasks=tasks)
    try:
        deadline = time.monotonic() + 5.0
        while len(attempts) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert len(attempts) >= 2, "scheduler thread died on the first failure"
        assert maintenance.is_scheduler_running()
    finally:
        maintenance.stop_background_scheduler()
