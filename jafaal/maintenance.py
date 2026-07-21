"""Auth-owned maintenance tasks for scheduler integration.

This module is the single coherent surface a background scheduler uses to
run recurring auth cleanup jobs. Routing every scheduled auth cleanup through
here keeps the host's scheduler from importing a scatter of low-level auth
``*.utils`` modules directly and gives auth one place to own its maintenance
contract.

Each name below is a callable the host schedules on its own cadence; they
are re-exported unchanged so their sync/async nature and arguments are
preserved.
"""

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
    "cleanup_expired_pending_mfa_logins",
    "cleanup_expired_rotated_tokens",
    "cleanup_idle_sessions",
    "delete_expired_oauth_states_from_db",
    "delete_idp_link_expired_tokens_from_db",
    "delete_invalid_password_reset_tokens_from_db",
    "delete_invalid_sign_up_tokens_from_db",
]


def cleanup_expired_pending_mfa_logins() -> int:
    """Evict expired pending MFA login entries."""
    return jafaal_security_stores.cleanup_expired_pending_mfa_logins()
