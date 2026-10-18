"""Fail-closed Backhaul update admission before any DB commit or restart.

Standard Backhaul must not silently lose its opt-in flag or replace its
loopback-only port mappings during an edit. The validator does not start,
stop, or mutate any service.
"""
from __future__ import annotations

from app.uopti_backhaul_standard import (
    StandardBackhaulSpecError, compile_standard_specs,
)


def review_backhaul_edit(
    *, core: str, old_spec: dict | None, proposed_spec: dict | None,
) -> bool:
    """Return True only for an already opted-in, fully checked Standard spec."""
    if core != "backhaul" or proposed_spec is None:
        return False
    old = isinstance(old_spec, dict) and old_spec.get("uopti_standard_backhaul") is True
    new = isinstance(proposed_spec, dict) and proposed_spec.get("uopti_standard_backhaul") is True
    if old and not new:
        raise StandardBackhaulSpecError("Standard Backhaul opt-in cannot be removed by edit")
    if new:
        compile_standard_specs(
            proposed_spec,
            data_port=proposed_spec.get("data_port", 56053),
            control_port=proposed_spec.get("control_port", 3080),
            bridge_port=proposed_spec.get("bridge_port", 13080),
        )
    return bool(new)
