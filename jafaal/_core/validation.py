"""Shared validation helpers for JAFAAL routers."""

from fastapi import HTTPException, status


def validate_id(identifier: int, min_value: int, message: str) -> None:
    """Validate that an integer identifier is above a minimum.

    Args:
        identifier: Identifier value to validate.
        min_value: Minimum exclusive value.
        message: Error detail for invalid values.

    Raises:
        HTTPException: 422 if the value is not above the minimum.
    """
    if not (int(identifier) > min_value):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=message,
        )
