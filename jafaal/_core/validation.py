"""Shared validation helpers for JAFAAL routers."""

import jafaal.exceptions as jafaal_exceptions


def validate_id(identifier: int, min_value: int, message: str) -> None:
    """Validate that an integer identifier is above a minimum.

    Args:
        identifier: Identifier value to validate.
        min_value: Minimum exclusive value.
        message: Error detail for invalid values.

    Raises:
        UnprocessableError: 422 if the value is not above the minimum.
    """
    if not (int(identifier) > min_value):
        raise jafaal_exceptions.UnprocessableError(message)
