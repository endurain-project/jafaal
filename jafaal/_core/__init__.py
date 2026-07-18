"""Vendored, dependency-free utilities owned by JAFAAL.

This package holds small primitives that JAFAAL previously imported from the
host application's ``core.*`` package. They are self-contained (standard
library, SQLAlchemy, and FastAPI only) so the library carries no dependency
on any particular host project.

JAFAAL emits logs via the standard library (``logging.getLogger(__name__)``)
directly in each module; there is no logging wrapper here. Host applications
configure handlers on the ``jafaal`` logger tree to capture output.

Modules:
    hashing: SHA-256 hex digest helper.
    validation: FastAPI id validation helper.
    db_errors: ``handle_db_errors`` decorator for CRUD functions.
"""
