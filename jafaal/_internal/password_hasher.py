"""Password hashing, verification, and policy enforcement.

Defines :class:`PasswordHasher` (Argon2-first with bcrypt fallback for legacy
hashes), :class:`PasswordPolicyError`, and the singleton accessor used as a
FastAPI dependency.
"""

import secrets
import string
from collections.abc import Iterable
from typing import Protocol, cast

from pwdlib import PasswordHash
from pwdlib.hashers import HasherProtocol
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

import jafaal.settings as jafaal_settings
from jafaal.exceptions import PasswordPolicyError


class SupportsHashPassword(Protocol):
    """Structural protocol for objects that can hash a password."""

    def hash_password(self, password: str) -> str: ...


class SupportsVerifyPassword(Protocol):
    """Structural protocol for objects that can verify a password against a hash."""

    def verify_password(self, password: str, password_hash: str) -> bool: ...


class PasswordHasher:
    """
    PasswordHasher provides secure password hashing, verification, and password policy enforcement.

    This class encapsulates password hashing logic, verification, and secure password generation
    according to strong password policies. It supports pluggable hashers and ensures that generated
    or validated passwords meet complexity requirements (uppercase, lowercase, digit, punctuation).

    Attributes:
        UPPER (str): All uppercase ASCII letters.
        LOWER (str): All lowercase ASCII letters.
        DIGITS (str): All ASCII digits.
        PUNCTUATION (str): All ASCII punctuation characters.
        ALL (str): Combination of all allowed characters.

    Methods:
        __init__(hasher: Argon2Hasher | BcryptHasher | None = None):
            Initializes the PasswordHasher with an optional custom hasher.

        hash_password(password: str) -> str:
            Hashes a plain text password using the configured password hashing algorithm.

        verify_password(plain_password: str, hashed_password: str) -> bool:
            Verifies if a plain password matches the given hashed password.

        verify_and_update(plain_password: str, hashed_password: str) -> tuple[bool, str | None]:
            Verifies a password and updates the hash if the algorithm or parameters have changed.

        generate_password(length: int = 8) -> str:
            Generates a secure random password of specified length, ensuring complexity.

        validate_password(password: str, min_length: int = 8) -> None:
            Validates that a password meets the required security policy, raising PasswordPolicyError if not.

        is_valid_password(password: str, min_length: int = 8) -> bool:
            Checks if a password meets the specified minimum length and password policy requirements.

    Example:
        try:
            PasswordHasher.validate_password("weak")
        except PasswordPolicyError as e:
            print("Oops:", e)
    """

    # Character classes
    UPPER = string.ascii_uppercase
    LOWER = string.ascii_lowercase
    DIGITS = string.digits
    PUNCTUATION = string.punctuation
    ALL = UPPER + LOWER + DIGITS + PUNCTUATION

    def __init__(
        self,
        hasher: (Argon2Hasher | BcryptHasher | Iterable[object] | PasswordHash | None) = None,
    ):
        """
        Initialize the password hasher configuration.
        Args:
            hasher (Argon2Hasher | BcryptHasher | Iterable[object] | PasswordHash | None, optional):
                The hasher(s) to use for password hashing. Can be:
                - None: Uses the strongest recommended configuration.
                - PasswordHash: Uses the provided PasswordHash instance.
                - Argon2Hasher or BcryptHasher: Uses the single hasher instance.
                - Iterable: Uses a list of hasher instances.
        Raises:
            TypeError: If the provided hasher is not of a supported type.
        """

        if hasher is None:
            # Default: strongest recommended config
            self._password_hash = PasswordHash.recommended()
        elif isinstance(hasher, PasswordHash):
            # Already a PasswordHash instance
            self._password_hash = hasher
        elif isinstance(hasher, (Argon2Hasher, BcryptHasher)):
            # Single hasher instance
            self._password_hash = PasswordHash([hasher])
        elif isinstance(hasher, Iterable):
            # Iterable of hashers
            self._password_hash = PasswordHash(cast(list[HasherProtocol], list(hasher)))
        else:
            raise TypeError(
                f"Unsupported hasher type: {type(hasher).__name__}. Must be Argon2Hasher, BcryptHasher, Iterable, PasswordHash, or None."
            )

        # Pre-compute the dummy hash now so dummy_verify() costs exactly one
        # verify on every call — including the first. Otherwise the first
        # "user not found" login would additionally pay the (deliberately slow)
        # hash and be measurably slower than the steady-state "found, wrong
        # password" branch, re-opening the username-enumeration timing side
        # channel that dummy_verify() exists to close.
        self._dummy_hash = self._password_hash.hash(secrets.token_urlsafe(32))

    def hash_password(self, password: str) -> str:
        """
        Hashes the provided password using the configured password hashing algorithm.

        Args:
            password (str): The plain text password to be hashed.

        Returns:
            str: The resulting hashed password.
        """
        return self._password_hash.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verifies whether the provided plain text password matches the given hashed password.

        Args:
            plain_password (str): The plain text password to verify.
            hashed_password (str): The hashed password to compare against.

        Returns:
            bool: True if the plain password matches the hashed password, False otherwise.
        """
        return self._password_hash.verify(plain_password, hashed_password)

    def verify_and_update(self, plain_password: str, hashed_password: str) -> tuple[bool, str | None]:
        """
        Verifies a plain password against a hashed password and updates the hash if necessary.

        Args:
            plain_password (str): The plain text password to verify.
            hashed_password (str): The hashed password to verify against.

        Returns:
            tuple[bool, str | None]: A tuple where the first element is a boolean indicating
            whether the password is correct, and the second element is the updated hash if
            the hash algorithm has changed or None otherwise.
        """
        return self._password_hash.verify_and_update(plain_password, hashed_password)

    def dummy_verify(self) -> None:
        """Run a constant-time-equivalent password verify against a dummy hash.

        Used by the login and MFA-verify endpoints on the "username/user
        not found" branch to equalise wall-clock latency with the
        "found, wrong password" branch. Without this, an unauthenticated
        attacker can enumerate valid usernames by measuring response
        time, because Argon2 is deliberately tuned to hundreds of
        milliseconds and a fast bail-out on the not-found branch is
        trivially distinguishable from a real verify.

        The dummy hash is pre-computed once at construction (see
        :meth:`__init__`), so this call always costs exactly one verify —
        the first invocation is not slower than steady state. A fresh
        random password is verified against it, so the result is always
        ``False``; the return value is ignored (the call exists purely
        for its timing side effect).
        """
        # Verify a random string against the pre-computed dummy hash: it is
        # guaranteed to return False but performs the full Argon2 verify work.
        self._password_hash.verify(secrets.token_urlsafe(32), self._dummy_hash)

    @staticmethod
    def generate_password(length: int = 8) -> str:
        """
        Generate a secure random password of specified length.

        The generated password will contain at least one uppercase letter, one lowercase letter,
        one digit, and one punctuation character to ensure complexity. The remaining characters
        are randomly selected from all allowed character sets.

        Args:
            length (int): The desired length of the password. Must be at least 8.

        Returns:
            str: A randomly generated password meeting the specified criteria.

        Raises:
            PasswordPolicyError: If the requested length is less than 8.
        """
        if length < 8:
            raise PasswordPolicyError(f"Requested length {length!r} is too short; must be ≥ 8.")

        # Guarantee at least one from each category
        chars = [
            secrets.choice(PasswordHasher.UPPER),
            secrets.choice(PasswordHasher.LOWER),
            secrets.choice(PasswordHasher.DIGITS),
            secrets.choice(PasswordHasher.PUNCTUATION),
        ]
        for _ in range(length - 4):
            chars.append(secrets.choice(PasswordHasher.ALL))
        secrets.SystemRandom().shuffle(chars)
        return "".join(chars)

    @staticmethod
    def validate_password(
        password: str,
        min_length: int = 8,
        policy_type: str = "strict",
        max_length: int | None = None,
    ) -> None:
        """
        Validates whether the given password meets the required security policy.

        Args:
            password (str): The password string to validate.
            min_length (int, optional): The minimum required length for the password. Defaults to 8.
            policy_type (str, optional): The password policy type to enforce.
                - "strict": Requires uppercase, lowercase, digit, and special character.
                - "length_only": Only enforces minimum/maximum length.
                Defaults to "strict".
            max_length (int | None, optional): The maximum accepted length. When
                provided, the password is rejected before hashing if it exceeds
                this bound. ``None`` (the default) enforces no maximum.

        Raises:
            PasswordPolicyError: If the password does not meet the policy requirements.

        Notes:
            - NIST SP 800-63B advises against imposing composition rules and in
              favour of length plus breach screening. ``"length_only"`` is the
              standards-aligned choice; pair it with a longer ``min_length`` and,
              ideally, a host-side breached-password check. ``"strict"`` remains
              available for hosts bound by legacy composition requirements.
            - The password is never truncated. The legacy bcrypt verifier
              silently truncates at 72 bytes, so a ``max_length`` above 72 only
              fully applies to Argon2 hashes (used for all new passwords).
        """
        if len(password) < min_length:
            raise PasswordPolicyError(f"Password is too short (got {len(password)}, need ≥ {min_length}).")

        # Bound the length before any (deliberately slow) hashing work and to keep
        # long passphrases supported (NIST SP 800-63B) without accepting unbounded
        # input.
        if max_length is not None and len(password) > max_length:
            raise PasswordPolicyError(f"Password is too long (got {len(password)}, allowed ≤ {max_length}).")

        # For length_only policy, only length is enforced
        if policy_type == "length_only":
            return

        # For strict policy, enforce complexity requirements
        if policy_type == "strict":
            if not any(c.isupper() for c in password):
                raise PasswordPolicyError("Password must contain at least one uppercase letter (A-Z).")

            if not any(c.islower() for c in password):
                raise PasswordPolicyError("Password must contain at least one lowercase letter (a-z).")

            if not any(c.isdigit() for c in password):
                raise PasswordPolicyError("Password must contain at least one digit (0-9).")

            if not any(c in PasswordHasher.PUNCTUATION for c in password):
                raise PasswordPolicyError(
                    f"Password must contain at least one special character ({PasswordHasher.PUNCTUATION})."
                )
        else:
            raise PasswordPolicyError(
                f"Unknown password policy type: {policy_type!r}. Supported types: 'strict', 'length_only'."
            )

    @staticmethod
    def is_valid_password(
        password: str,
        min_length: int = 8,
        policy_type: str = "strict",
        max_length: int | None = None,
    ) -> bool:
        """
        Checks if the provided password meets the specified minimum length and password policy requirements.

        Args:
            password (str): The password string to validate.
            min_length (int, optional): The minimum required length for the password. Defaults to 8.
            policy_type (str, optional): The password policy type to enforce. Defaults to "strict".
            max_length (int | None, optional): The maximum accepted length, or ``None`` for no maximum.

        Returns:
            bool: True if the password is valid according to the policy, False otherwise.
        """
        try:
            PasswordHasher.validate_password(password, min_length, policy_type, max_length)
            return True
        except PasswordPolicyError:
            return False


def get_password_hasher() -> PasswordHasher:
    """Return the process-wide password hasher.

    When JAFAAL is configured, the hasher is built from the Argon2 cost
    parameters in :class:`~jafaal.settings.AuthSettings` (``argon2_time_cost`` /
    ``argon2_memory_cost`` / ``argon2_parallelism``), cached, and transparently
    rebuilt if :func:`jafaal.configure` is called again (mirroring
    ``get_token_manager``). Before configuration it falls back to the
    default-cost singleton, so isolated password hashing/verification works
    without installing settings. Argon2/bcrypt hashes are self-describing, so a
    hash produced at one cost still verifies (and is transparently upgraded via
    ``verify_and_update``) at another.

    Returns:
        PasswordHasher: The active password hasher.
    """
    global _settings_password_hasher, _settings_password_hasher_generation
    if not jafaal_settings.is_configured():
        return password_hasher
    generation = jafaal_settings.settings_generation()
    if _settings_password_hasher is None or _settings_password_hasher_generation != generation:
        settings = jafaal_settings.get_settings()
        _settings_password_hasher = PasswordHasher(
            hasher=[
                Argon2Hasher(
                    time_cost=settings.argon2_time_cost,
                    memory_cost=settings.argon2_memory_cost,
                    parallelism=settings.argon2_parallelism,
                ),
                BcryptHasher(),
            ]
        )
        _settings_password_hasher_generation = generation
    return _settings_password_hasher


# Initialize the PasswordHasher with both Argon2 and Bcrypt support
# Argon2 listed first => new hashes use Argon2; bcrypt remains verifiable for legacy rows.
# This default-cost instance is used before settings are installed (and is
# imported directly by tests); get_password_hasher() returns a settings-tuned
# instance once jafaal.configure has run.
password_hasher = PasswordHasher(hasher=[Argon2Hasher(), BcryptHasher()])

# Cached settings-derived hasher (rebuilt on settings-generation bump).
_settings_password_hasher: PasswordHasher | None = None
_settings_password_hasher_generation: int = -1
