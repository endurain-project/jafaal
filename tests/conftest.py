"""Shared test setup.

``import jafaal`` runs standalone since Phase 5 — the ``StateStore`` port ships a
process-local :class:`~jafaal.state_store.InMemoryStateStore` default, so no host
state backend stub is required.
"""
