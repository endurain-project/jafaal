"""Authenticated self-service MFA management endpoints."""

from typing import Annotated

from fastapi import Depends, Response, Security, status
from sqlalchemy.orm import Session

import jafaal._internal.security_stores as jafaal_security_stores
import jafaal._internal.services.mfa_workflow as mfa_workflow
import jafaal.dependencies as jafaal_dependencies
import jafaal.identity_service as jafaal_identity_service
import jafaal.mfa.backup_codes.schema as mfa_backup_codes_schema
import jafaal.mfa.schema as mfa_schema
import jafaal.mfa.setup_store as mfa_setup_store
import jafaal.orm as jafaal_orm
import jafaal.rate_limit as jafaal_rate_limit
import jafaal.schema as jafaal_schema
import jafaal.utils as jafaal_utils
from jafaal.orm import UserId
from jafaal.principal import Principal

router = jafaal_orm.auth_router()


def _user_id(principal: Principal) -> UserId:
    return principal.user_id


@router.get("/mfa", response_model=mfa_schema.MFAStatusResponse)
def get_mfa_status(
    _check_scope: Annotated[None, Security(jafaal_dependencies.check_scopes, scopes=["profile"])],
    principal: Annotated[Principal, Depends(jafaal_dependencies.get_current_principal)],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> mfa_schema.MFAStatusResponse:
    """Return the authenticated user's TOTP MFA status."""
    return mfa_workflow.get_mfa_status(_user_id(principal), db)


@router.post("/mfa/setup", response_model=mfa_schema.MFASetupResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def setup_mfa(
    response: Response,
    _check_scope: Annotated[None, Security(jafaal_dependencies.check_scopes, scopes=["profile"])],
    principal: Annotated[Principal, Depends(jafaal_dependencies.get_current_principal)],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    secret_store: Annotated[mfa_setup_store.MFASecretStore, Depends(mfa_setup_store.get_mfa_secret_store)],
) -> mfa_schema.MFASetupResponse:
    """Create pending TOTP enrollment material for the authenticated user."""
    jafaal_utils.apply_no_store(response)
    return mfa_workflow.setup_mfa(_user_id(principal), db, secret_store)


@router.post("/mfa/enable", response_model=mfa_schema.MFAEnableResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def enable_mfa(
    response: Response,
    request: mfa_schema.MFASetupRequest,
    _check_scope: Annotated[None, Security(jafaal_dependencies.check_scopes, scopes=["profile"])],
    principal: Annotated[Principal, Depends(jafaal_dependencies.get_current_principal)],
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    step_up_store: Annotated[
        jafaal_security_stores.StepUpStore,
        Depends(jafaal_security_stores.get_step_up_attempts),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
    secret_store: Annotated[mfa_setup_store.MFASecretStore, Depends(mfa_setup_store.get_mfa_secret_store)],
) -> dict:
    """Verify pending enrollment and enable TOTP MFA."""
    jafaal_utils.apply_no_store(response)
    return mfa_workflow.enable_mfa(
        request,
        _user_id(principal),
        identity_service,
        step_up_store,
        db,
        secret_store,
    )


@router.post("/mfa/disable", response_model=mfa_schema.MFAActionResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def disable_mfa(
    request: mfa_schema.MFADisableRequest,
    _check_scope: Annotated[None, Security(jafaal_dependencies.check_scopes, scopes=["profile"])],
    principal: Annotated[Principal, Depends(jafaal_dependencies.get_current_principal)],
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    step_up_store: Annotated[
        jafaal_security_stores.StepUpStore,
        Depends(jafaal_security_stores.get_step_up_attempts),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> dict:
    """Disable TOTP MFA after step-up verification."""
    return mfa_workflow.disable_mfa(
        request,
        _user_id(principal),
        identity_service,
        step_up_store,
        db,
    )


@router.post("/mfa/verify", response_model=mfa_schema.MFAActionResponse)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def verify_mfa(
    request: mfa_schema.MFARequest,
    _check_scope: Annotated[None, Security(jafaal_dependencies.check_scopes, scopes=["profile"])],
    principal: Annotated[Principal, Depends(jafaal_dependencies.get_current_principal)],
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> dict:
    """Verify a TOTP or backup code for the authenticated user."""
    return mfa_workflow.verify_mfa(request, _user_id(principal), identity_service, db)


@router.get("/mfa/backup-codes", response_model=mfa_backup_codes_schema.MFABackupCodeStatus)
def get_backup_code_status(
    _check_scope: Annotated[None, Security(jafaal_dependencies.check_scopes, scopes=["profile"])],
    principal: Annotated[Principal, Depends(jafaal_dependencies.get_current_principal)],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> mfa_backup_codes_schema.MFABackupCodeStatus:
    """Return aggregate backup-code status without exposing stored codes."""
    return mfa_workflow.get_backup_code_status(_user_id(principal), db)


@router.post(
    "/mfa/backup-codes",
    response_model=mfa_backup_codes_schema.MFABackupCodesResponse,
    status_code=status.HTTP_201_CREATED,
)
@jafaal_rate_limit.limit(jafaal_rate_limit.SENSITIVE)
def generate_backup_codes(
    response: Response,
    request: jafaal_schema.StepUpVerification,
    _check_scope: Annotated[None, Security(jafaal_dependencies.check_scopes, scopes=["profile"])],
    principal: Annotated[Principal, Depends(jafaal_dependencies.get_current_principal)],
    identity_service: Annotated[
        jafaal_identity_service.LocalCredentialStore,
        Depends(jafaal_identity_service.get_identity_service),
    ],
    step_up_store: Annotated[
        jafaal_security_stores.StepUpStore,
        Depends(jafaal_security_stores.get_step_up_attempts),
    ],
    db: Annotated[Session, Depends(jafaal_orm.get_db)],
) -> mfa_backup_codes_schema.MFABackupCodesResponse:
    """Replace backup codes after step-up verification and return them once."""
    jafaal_utils.apply_no_store(response)
    return mfa_workflow.generate_backup_codes(
        request,
        _user_id(principal),
        identity_service,
        step_up_store,
        db,
    )
