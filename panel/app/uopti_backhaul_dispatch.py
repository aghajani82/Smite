"""Secure, opt-in Standard Backhaul dispatch for BOTH signed and legacy modes.

Never trust caller-supplied Backhaul node payloads. Rebuild only for an
admin-approved persisted tunnel with explicit uopti_standard_backhaul.
Run BEFORE the NodeClient signed/legacy split, so the signed path cannot
accidentally bypass the canonical compiler previously injected by U-OPTI
into the legacy-only send_to_node branch.

This module performs no service changes; it returns a new payload object.
"""
from __future__ import annotations

from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models import Node, Tunnel
from app.uopti_backhaul_standard import (
    StandardBackhaulSpecError, compile_standard_specs,
)


def compile_dispatch_payload(
    *, node_role: str | None, stored_spec: dict | None,
    endpoint: str, incoming: dict,
) -> dict:
    if endpoint != "/api/agent/tunnels/apply" or incoming.get("core") != "backhaul":
        return incoming
    opted = (
        isinstance(stored_spec, dict)
        and stored_spec.get("uopti_standard_backhaul") is True
    )
    requested = (
        isinstance(incoming.get("spec"), dict)
        and incoming["spec"].get("uopti_standard_backhaul") is True
    )
    if not opted:
        if requested:
            raise StandardBackhaulSpecError(
                "Standard Backhaul requires a persisted opted-in tunnel"
            )
        return incoming
    if node_role not in ("iran", "foreign"):
        raise StandardBackhaulSpecError("Unrecognized paired Node role")
    server, client = compile_standard_specs(
        stored_spec,
        data_port=stored_spec.get("data_port", 56053),
        control_port=stored_spec.get("control_port", 3080),
        bridge_port=stored_spec.get("bridge_port", 13080),
    )
    outgoing = dict(incoming)
    outgoing["spec"] = server if node_role == "iran" else client
    return outgoing


async def prepare_node_command(node_id: str, endpoint: str, incoming: dict) -> dict:
    """Pass through non-Backhaul commands, including FRP, without DB queries."""
    if (
        endpoint != "/api/agent/tunnels/apply"
        or not isinstance(incoming, dict)
        or incoming.get("core") != "backhaul"
    ):
        return incoming
    tunnel_id = incoming.get("tunnel_id")
    if not isinstance(tunnel_id, str) or not tunnel_id:
        raise StandardBackhaulSpecError("Backhaul tunnel UUID required")
    async with AsyncSessionLocal() as session:
        node_result = await session.execute(select(Node).where(Node.id == node_id))
        node = node_result.scalar_one_or_none()
        if node is None:
            raise StandardBackhaulSpecError("Unknown Node")
        tunnel_result = await session.execute(
            select(Tunnel).where(Tunnel.id == tunnel_id)
        )
        tunnel = tunnel_result.scalar_one_or_none()
        if tunnel is None or tunnel.core != "backhaul":
            raise StandardBackhaulSpecError("Unknown persisted Backhaul tunnel")
        return compile_dispatch_payload(
            node_role=(node.node_metadata or {}).get("role"),
            stored_spec=tunnel.spec, endpoint=endpoint, incoming=incoming,
        )
