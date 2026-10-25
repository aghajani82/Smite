"""Synchronous, fail-closed preflight for managed FRPS server admission.

This does not implement shared child Apply. Until reviewed signed child
orchestration exists, it explicitly denies child flags and duplicate owners
BEFORE any tunnel database creation or signed remote Apply.
"""
from __future__ import annotations
from collections.abc import Iterable, Mapping
from typing import Any


class FrpsServerAdmissionDenied(ValueError):
    """Public-safe operator message, free of credentials and identity data."""


def _control_port(spec: Mapping[str, Any]) -> int:
    value = spec.get("bind_port", 7000)
    if isinstance(value, bool):
        raise FrpsServerAdmissionDenied("Invalid FRPS control port")
    try:
        port = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise FrpsServerAdmissionDenied("Invalid FRPS control port") from exc
    if not 1 <= port <= 65535:
        raise FrpsServerAdmissionDenied("Invalid FRPS control port")
    return port


def require_exclusive_frps_server_admission(
    *,
    candidate_spec: Mapping[str, Any],
    owner_node_id: str,
    existing_tunnels: Iterable[Any],
    current_tunnel_id: str | None = None,
) -> None:
    if not isinstance(candidate_spec, Mapping) or not owner_node_id:
        raise FrpsServerAdmissionDenied("Missing FRPS server admission data")
    if "shared_frps_owner" in candidate_spec:
        # A marker without a separate signed *client-only* lifecycle is NOT
        # permission to make another FRPS or reuse arbitrary credentials.
        raise FrpsServerAdmissionDenied(
            "Shared FRPS proxy Apply is not enabled in this release"
        )
    port = _control_port(candidate_spec)
    for tunnel in existing_tunnels:
        if getattr(tunnel, "core", None) != "frp":
            continue
        if current_tunnel_id is not None and getattr(tunnel, "id", None) == current_tunnel_id:
            continue
        if getattr(tunnel, "status", None) not in ("active", "pending"):
            continue
        existing_node = (
            getattr(tunnel, "iran_node_id", None)
            or getattr(tunnel, "node_id", None)
        )
        if existing_node != owner_node_id:
            continue
        previous_spec = getattr(tunnel, "spec", None)
        if not isinstance(previous_spec, Mapping):
            # Unknown ownership of an active FRP tunnel: fail closed.
            raise FrpsServerAdmissionDenied(
                "Existing FRPS ownership is not verifiable"
            )
        if _control_port(previous_spec) == port:
            raise FrpsServerAdmissionDenied(
                "FRPS control port already owned; second FRPS refused"
            )
