"""Smoke tests for the maintenance task surface (scheduler entry points)."""

import jafaal.maintenance as maintenance


def test_all_exports_are_callable():
    for name in maintenance.__all__:
        assert callable(getattr(maintenance, name))


def test_cleanup_tasks_run_on_empty_db():
    # Each opens its own session_scope; with empty tables they are no-ops and
    # must not raise.
    maintenance.cleanup_expired_pending_mfa_logins()
    maintenance.cleanup_expired_rotated_tokens()
    maintenance.cleanup_idle_sessions()
    maintenance.delete_expired_oauth_states_from_db()
    maintenance.delete_idp_link_expired_tokens_from_db()
    maintenance.delete_invalid_password_reset_tokens_from_db()
    maintenance.delete_invalid_sign_up_tokens_from_db()
