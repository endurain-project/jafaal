"""Vendored, dependency-free utilities owned by JAFAAL.

This package holds small primitives that JAFAAL previously imported from the
host application's ``core.*`` package. They are self-contained (standard
library, SQLAlchemy, and FastAPI only) so the library carries no dependency
on any particular host project.

Modules:
    logger: Standard-library logging shim (``print_to_log``).
    hashing: SHA-256 hex digest helper.
    validation: FastAPI id validation helper.
    db_errors: ``handle_db_errors`` decorator for CRUD functions.
"""
