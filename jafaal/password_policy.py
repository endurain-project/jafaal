"""Auth-owned password policy helpers.

Resolves the host's password policy (via the :class:`~jafaal.ports.SettingsProvider`
port) into the correct minimum length for the account's tier and delegates
validate+hash to the IdentityService.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import jafaal.ports as jafaal_ports
import jafaal.settings as jafaal_settings

if TYPE_CHECKING:
    import jafaal.identity_service as jafaal_identity_service


def validate_and_hash_for_user(
    identity_service: jafaal_identity_service.IdentityService,
    is_superuser: bool,
    password: str,
) -> str:
    """
    Validate and hash a password using the account's tier policy.

    Args:
        identity_service: Identity service for hashing.
        is_superuser: Whether the account is an admin/superuser (selects the
            admin minimum length rather than the regular one).
        password: Plaintext password to validate and hash.

    Returns:
        The hashed password string.

    Raises:
        JafaalError: If the password fails validation.
    """
    policy = jafaal_ports.get_settings_provider().get_password_policy()
    min_length = policy.min_length_for(is_superuser=is_superuser)
    max_length = jafaal_settings.get_settings().password_max_length
    return identity_service.validate_and_hash_password(password, min_length, policy.password_type, max_length)
