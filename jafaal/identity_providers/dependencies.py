"""Identity provider-specific request validation dependencies."""

from jafaal._core import validation


def validate_idp_id(idp_id: int) -> None:
    """
    Validate that identity provider ID is positive.

    Args:
        idp_id: Identity provider ID to validate.

    Returns:
        None

    Raises:
        JafaalError: 400 if identity provider ID is invalid (≤ 0).
    """
    validation.validate_id(identifier=idp_id, min_value=0, message="Invalid identity provider ID")
