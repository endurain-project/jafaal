"""Shared test setup.

Stubs the host ``infra.*`` state backend so ``import jafaal`` works standalone.
Temporary until Phase 5 introduces the ``StateStore`` port (see plan §2.7).
"""

import sys
import types

for _name in ("infra", "infra.runtime", "infra.providers"):
    sys.modules.setdefault(_name, types.ModuleType(_name))


class _StateBackendUnavailableError(Exception):
    pass


class _StateProvider:  # minimal placeholder
    ...


sys.modules["infra.providers"].StateBackendUnavailableError = _StateBackendUnavailableError
sys.modules["infra.providers"].StateProvider = _StateProvider
