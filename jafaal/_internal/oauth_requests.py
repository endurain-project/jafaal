"""Raw OAuth request parsing that preserves repeated parameters."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from fastapi import Request
from starlette.exceptions import HTTPException as StarletteHTTPException

import jafaal.exceptions as jafaal_exceptions


def invalid_request(detail: str) -> jafaal_exceptions.OAuthError:
    """Build an RFC 6749 ``invalid_request`` error."""
    return jafaal_exceptions.OAuthError("invalid_request", detail)


@dataclass(frozen=True)
class OAuthRequestParameters:
    """OAuth parameters grouped without collapsing repeated names."""

    values: dict[str, tuple[str, ...]]

    @classmethod
    def from_items(cls, items: Iterable[tuple[str, object]]) -> OAuthRequestParameters:
        grouped: defaultdict[str, list[str]] = defaultdict(list)
        for name, value in items:
            if not isinstance(value, str):
                raise invalid_request(f"Request parameter {name!r} must be a text value.")
            grouped[name].append(value)
        return cls({name: tuple(values) for name, values in grouped.items()})

    def reject_duplicates(self, names: Iterable[str] | None = None) -> None:
        """Reject selected parameter names that occur more than once."""
        selected = self.values if names is None else names
        repeated = sorted(name for name in selected if len(self.values.get(name, ())) > 1)
        if repeated:
            names = ", ".join(repr(name) for name in repeated)
            noun = "parameter" if len(repeated) == 1 else "parameters"
            raise invalid_request(f"Request {noun} {names} must not appear more than once.")

    def required(self, name: str) -> str:
        """Return one non-empty required parameter."""
        value = self.optional(name)
        if not value:
            raise invalid_request(f"{name!r} is required.")
        return value

    def optional(self, name: str) -> str | None:
        """Return an optional parameter after duplicate validation."""
        values = self.values.get(name)
        return values[0] if values else None

    def unambiguous(self, name: str) -> str | None:
        """Return a value only when its name occurs exactly once."""
        values = self.values.get(name)
        return values[0] if values is not None and len(values) == 1 else None


@dataclass(frozen=True)
class OAuthTokenRequest:
    """Parsed fields accepted by JAFAAL's RFC 6749 token endpoint."""

    grant_type: str
    code: str | None
    code_verifier: str | None
    redirect_uri: str | None
    client_id: str | None
    refresh_token: str | None


@dataclass(frozen=True)
class OAuthIntrospectionRequest:
    """Parsed RFC 7662 introspection request."""

    token: str
    token_type_hint: str | None


@dataclass(frozen=True)
class OAuthRevocationRequest:
    """Parsed RFC 7009 revocation request."""

    token: str
    client_id: str | None
    token_type_hint: str | None


async def parse_oauth_form(request: Request) -> OAuthRequestParameters:
    """Parse a form body and translate parser failures to OAuth errors."""
    try:
        form = await request.form()
    except (StarletteHTTPException, UnicodeError, ValueError) as err:
        raise invalid_request("The request body is not valid form data.") from err
    return OAuthRequestParameters.from_items(form.multi_items())


def parse_oauth_query(request: Request) -> OAuthRequestParameters:
    """Parse a query string without collapsing repeated parameter names."""
    return OAuthRequestParameters.from_items(request.query_params.multi_items())


async def parse_token_request(request: Request) -> OAuthTokenRequest:
    """Parse and validate the common token-request boundary."""
    parameters = await parse_oauth_form(request)
    parameters.reject_duplicates()
    return OAuthTokenRequest(
        grant_type=parameters.required("grant_type"),
        code=parameters.optional("code"),
        code_verifier=parameters.optional("code_verifier"),
        redirect_uri=parameters.optional("redirect_uri"),
        client_id=parameters.optional("client_id"),
        refresh_token=parameters.optional("refresh_token"),
    )


async def parse_introspection_request(request: Request) -> OAuthIntrospectionRequest:
    """Parse one duplicate-safe RFC 7662 form request."""
    parameters = await parse_oauth_form(request)
    parameters.reject_duplicates()
    return OAuthIntrospectionRequest(
        token=parameters.required("token"),
        token_type_hint=parameters.optional("token_type_hint"),
    )


async def parse_revocation_request(request: Request) -> OAuthRevocationRequest:
    """Parse one duplicate-safe RFC 7009 form request."""
    parameters = await parse_oauth_form(request)
    parameters.reject_duplicates()
    return OAuthRevocationRequest(
        token=parameters.required("token"),
        client_id=parameters.optional("client_id"),
        token_type_hint=parameters.optional("token_type_hint"),
    )
