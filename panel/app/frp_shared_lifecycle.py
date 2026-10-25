"""Signed-only shared FRPS child lifecycle with persistent unique leases.

The first FRPS owner's config, tunnel row and live process are NEVER modified
by a child Create, Apply or Remove. No legacy fallback. A failure keeps the
child row and allocated port for reconciliation; no automatic signed retries.
"""
from __future__ import annotations

from collections.abc import Mapping

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.frp_shared_server import (
    SharedFrpAdmissionDenied, plan_shared_frp_proxy, _child_pair,
)
from app.models import Tunnel, FrpProxyLease


def is_shared_child(spec) -> bool:
    return isinstance(spec, Mapping) and "shared_frps_owner" in spec


async def prepare_shared_child(*, db, client, iran_node, foreign_node,
                               child_spec, child_type, exclude_tunnel_id=None):
    """Check live *signed* FRPS owner and allocate only one client proxy plan."""
    if (settings.smite_engine_management_mode != "managed"
            or settings.smite_panel_agent_auth_mode != "signed"):
        raise HTTPException(409, "Shared FRPS requires signed managed Nodes")
    if not is_shared_child(child_spec):
        raise HTTPException(409, "Explicit shared FRPS owner required")
    owner_id = child_spec.get("shared_frps_owner")
    if not isinstance(owner_id, str) or not owner_id:
        raise HTTPException(409, "Shared FRPS owner invalid")
    owner = (await db.execute(
        select(Tunnel).where(Tunnel.id == owner_id)
    )).scalar_one_or_none()
    if owner is None:
        raise HTTPException(409, "Shared FRPS owner not found")
    owner_ir = owner.iran_node_id or owner.node_id
    if (owner_ir != iran_node.id
            or owner.foreign_node_id != foreign_node.id
            or owner.status != "active"):
        raise HTTPException(409, "Shared FRPS owner pair not active")

    # Require the actual owner process + loopback listener, not a stale
    # Smite DB Active flag. The Node proof is HMAC GET and never plaintext
    # WAN, anonymous legacy, a signing test POST or UI-supplied token.
    proof = await client.get_verified_frps_owners(iran_node.id)
    entries = proof.get("owners") if isinstance(proof, dict) and proof.get("status") == "success" else None
    if (not isinstance(entries, list) or len(entries) != 1
            or entries[0] != {"tunnel_id": owner.id, "control_port": 7000}):
        raise HTTPException(409, "Trusted FRPS owner runtime proof unavailable")

    siblings = (await db.execute(select(Tunnel).where(
        Tunnel.core == "frp"
    ))).scalars().all()
    occupied = []
    for entry in siblings:
        if entry.id == exclude_tunnel_id:
            continue
        if (entry.iran_node_id or entry.node_id) != iran_node.id:
            continue
        # An error or pending row may have applied before its response was
        # lost. Refuse reuse until explicitly reconciled/removed.
        try:
            _, reserved_port = _child_pair(entry.spec or {})
            occupied.append(reserved_port)
        except (ValueError, TypeError, KeyError, SharedFrpAdmissionDenied):
            raise HTTPException(409, "Existing FRP proxy port cannot be reconciled")

    addr = (iran_node.node_metadata or {}).get("ip_address")
    try:
        return plan_shared_frp_proxy(
            owner_tunnel_id=owner.id,
            requested_owner_tunnel_id=owner_id,
            owner_node_id=owner_ir,
            child_node_id=iran_node.id,
            owner_status=owner.status,
            owner_core=owner.core,
            owner_type=owner.type,
            owner_spec=owner.spec or {},
            child_spec=child_spec,
            child_type=child_type,
            occupied_remote_ports=occupied,
            server_addr=addr,
        )
    except (SharedFrpAdmissionDenied, TypeError, ValueError) as exc:
        # Do not reflect potentially sensitive user-supplied values or spec.
        raise HTTPException(409, "Shared FRPS proxy admission denied") from exc


async def send_shared_child_apply(*, db, tunnel, client, plan):
    """Issue a single signed KH client Apply. No IR Apply/remove/restart."""
    response = await client.send_to_node(
        tunnel.foreign_node_id, "/api/agent/tunnels/apply",
        {
            "tunnel_id": tunnel.id,
            "core": "frp",
            "type": "tcp",
            "spec": plan.client_spec,
        }
    )
    if isinstance(response, dict) and response.get("status") == "success":
        tunnel.status = "active"
        tunnel.error_message = None
    else:
        # A lost response may be a successful client Apply. Never retry
        # automatically and never release the unique allocation here.
        tunnel.status = "error"
        tunnel.error_message = "Foreign shared FRP client Apply not confirmed"
    await db.commit()
    await db.refresh(tunnel)
    return tunnel


async def create_shared_child(*, db, client, requested, iran_node, foreign_node):
    plan = await prepare_shared_child(
        db=db, client=client, iran_node=iran_node,
        foreign_node=foreign_node, child_spec=requested.spec,
        child_type=requested.type,
    )
    tunnel = Tunnel(
        name=requested.name, core="frp", type="tcp",
        node_id=iran_node.id, iran_node_id=iran_node.id,
        foreign_node_id=foreign_node.id,
        spec=requested.spec.copy(), status="pending",
    )
    db.add(tunnel)
    await db.flush()
    db.add(FrpProxyLease(
        tunnel_id=tunnel.id, iran_node_id=iran_node.id,
        foreign_node_id=foreign_node.id,
        owner_tunnel_id=plan.owner_tunnel_id,
        remote_port=plan.remote_port,
    ))
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "Shared FRPS remote port already reserved") from exc
    await db.refresh(tunnel)
    return await send_shared_child_apply(
        db=db, tunnel=tunnel, client=client, plan=plan,
    )


async def reapply_shared_child(*, db, client, tunnel):
    """No IR signed mutation. Require original unique lease and owner proof."""
    if tunnel.core != "frp" or not is_shared_child(tunnel.spec):
        raise HTTPException(409, "Not a shared FRPS child")
    from app.models import Node
    ir = (await db.execute(select(Node).where(
        Node.id == (tunnel.iran_node_id or tunnel.node_id)
    ))).scalar_one_or_none()
    kh = (await db.execute(select(Node).where(
        Node.id == tunnel.foreign_node_id
    ))).scalar_one_or_none()
    lease = (await db.execute(select(FrpProxyLease).where(
        FrpProxyLease.tunnel_id == tunnel.id
    ))).scalar_one_or_none()
    if ir is None or kh is None or lease is None:
        raise HTTPException(409, "Shared proxy identity or lease missing")
    if (lease.iran_node_id != ir.id or lease.foreign_node_id != kh.id
            or lease.owner_tunnel_id != tunnel.spec.get("shared_frps_owner")):
        raise HTTPException(409, "Shared proxy lease identity mismatch")
    plan = await prepare_shared_child(
        db=db, client=client, iran_node=ir, foreign_node=kh,
        child_spec=tunnel.spec, child_type=tunnel.type,
        exclude_tunnel_id=tunnel.id,
    )
    if plan.remote_port != lease.remote_port:
        raise HTTPException(409, "Shared proxy lease port mismatch")
    await send_shared_child_apply(
        db=db, tunnel=tunnel, client=client, plan=plan,
    )
    if tunnel.status != "active":
        raise HTTPException(409, "Foreign FRP client Apply not confirmed")
    return {"status": "applied", "message": "Shared FRP client applied without restarting owner"}


async def remove_shared_child(*, db, client, tunnel):
    """Delete only after a confirmed signed KH remove; IR owner untouched."""
    if not is_shared_child(tunnel.spec) or not tunnel.foreign_node_id:
        raise HTTPException(409, "Shared FRPS child pair invalid")
    if (settings.smite_engine_management_mode != "managed"
            or settings.smite_panel_agent_auth_mode != "signed"):
        raise HTTPException(409, "Shared proxy cleanup requires signed managed control")
    lease = (await db.execute(select(FrpProxyLease).where(
        FrpProxyLease.tunnel_id == tunnel.id
    ))).scalar_one_or_none()
    if (lease is None or lease.foreign_node_id != tunnel.foreign_node_id
            or lease.owner_tunnel_id != tunnel.spec.get("shared_frps_owner")
            or lease.iran_node_id != (tunnel.iran_node_id or tunnel.node_id)):
        # Never send a destructive command if the lease cannot be verified.
        raise HTTPException(409, "Shared FRP lease missing or mismatched")
    response = await client.send_to_node(
        tunnel.foreign_node_id, "/api/agent/tunnels/remove",
        {"tunnel_id": tunnel.id},
    )
    if not isinstance(response, dict) or response.get("status") != "success":
        raise HTTPException(409, "Shared FRP child cleanup unconfirmed")
    await db.delete(lease)
    await db.delete(tunnel)
    await db.commit()
    return {"status": "deleted"}
