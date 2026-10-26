"""Panel orchestration for the existing signed FRP → XHTTP route flow.

Only the child tunnel ID and selected KH inbound port are user supplied.
Owner, lease, Node identities, XHTTP path and evidence digests are read from
the signed Node APIs and Panel's durable records. The Broker still requires
its separately installed root-owned TrustedGrant before any host mutation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from fastapi import HTTPException
from sqlalchemy import select

from app.config import settings
from app.frp_shared_lifecycle import is_shared_child
from app.models import FrpProxyLease, Node, Tunnel
from app.xhttp_route_intent import (
    ApprovedRouteBinding, RouteIntentHold, sign_route_intent,
)


class XhttpRouteHold(RuntimeError):
    """A stable, non-secret refusal to register an XHTTP route."""


def _canonical_hash(value: object) -> str:
    raw = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _broker_key() -> bytes:
    """Read a separately mounted 32-byte key without following symlinks."""
    path = Path(settings.smite_uopti_route_broker_key_path)
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in (0o400, 0o600)
                or before.st_size != 32):
            raise XhttpRouteHold("BROKER_KEY_UNAVAILABLE")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise XhttpRouteHold("BROKER_KEY_CHANGED")
            key = os.read(fd, 33)
        finally:
            os.close(fd)
        if len(key) != 32:
            raise XhttpRouteHold("BROKER_KEY_UNAVAILABLE")
        return key
    except OSError as exc:
        raise XhttpRouteHold("BROKER_KEY_UNAVAILABLE") from exc


async def register_xhttp_route(*, db, tunnel_id: str, inbound_port: int,
                               client, now: int) -> dict[str, str]:
    """Verify current lease + signed IR/KH evidence, then send one intent.

    This is deliberately a single attempt. A lost/ambiguous response is HOLD;
    the caller must verify current state before another operator action.
    """
    if (type(inbound_port) is not int or not 1024 <= inbound_port <= 65535
            or inbound_port == 7000 or not isinstance(tunnel_id, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", tunnel_id)):
        raise XhttpRouteHold("INVALID_ROUTE_SELECTION")

    result = await db.execute(select(Tunnel).where(Tunnel.id == tunnel_id))
    child = result.scalar_one_or_none()
    if (child is None or child.core != "frp" or child.status != "active"
            or not is_shared_child(child.spec or {})):
        raise XhttpRouteHold("ACTIVE_SHARED_FRP_CHILD_REQUIRED")

    lease_result = await db.execute(select(FrpProxyLease).where(
        FrpProxyLease.tunnel_id == child.id
    ))
    lease = lease_result.scalar_one_or_none()
    if (lease is None or lease.tunnel_id != child.id
            or lease.iran_node_id != (child.iran_node_id or child.node_id)
            or lease.foreign_node_id != child.foreign_node_id
            or lease.owner_tunnel_id != child.spec.get("shared_frps_owner")
            or lease.remote_port != inbound_port):
        raise XhttpRouteHold("ACTIVE_UNIQUE_LEASE_MISMATCH")

    owner_result = await db.execute(select(Tunnel).where(
        Tunnel.id == lease.owner_tunnel_id
    ))
    owner = owner_result.scalar_one_or_none()
    if (owner is None or owner.core != "frp" or owner.status != "active"
            or (owner.iran_node_id or owner.node_id) != lease.iran_node_id
            or owner.foreign_node_id != lease.foreign_node_id):
        raise XhttpRouteHold("FRPS_OWNER_PAIR_MISMATCH")

    ir_result = await db.execute(select(Node).where(Node.id == lease.iran_node_id))
    ir = ir_result.scalar_one_or_none()
    kh_result = await db.execute(select(Node).where(Node.id == lease.foreign_node_id))
    kh = kh_result.scalar_one_or_none()
    if (ir is None or kh is None
            or (ir.node_metadata or {}).get("role") != "iran"
            or (kh.node_metadata or {}).get("role") != "foreign"):
        raise XhttpRouteHold("PAIRED_NODE_IDENTITY_MISMATCH")

    owner_response = await client.get_verified_frps_owners(ir.id)
    owners = (owner_response.get("owners") if isinstance(owner_response, dict)
              and owner_response.get("status") == "success" else None)
    if (not isinstance(owners, list) or len(owners) != 1
            or not isinstance(owners[0], dict)
            or owners[0].get("tunnel_id") != owner.id
            or owners[0].get("control_port") != 7000
            or not isinstance(owners[0].get("proxy_ports"), list)
            or any(type(port) is not int for port in owners[0]["proxy_ports"])
            or lease.remote_port not in owners[0]["proxy_ports"]):
        raise XhttpRouteHold("SIGNED_FRPS_OWNER_PROOF_MISMATCH")

    inventory_response = await client.get_signed_sanaei_xhttp_inbounds(kh.id)
    inbounds = (inventory_response.get("inbounds")
                if isinstance(inventory_response, dict)
                and inventory_response.get("status") == "success"
                and inventory_response.get("schema_version") == 1 else None)
    if not isinstance(inbounds, list):
        raise XhttpRouteHold("SIGNED_KH_INVENTORY_UNAVAILABLE")
    selected = [item for item in inbounds if isinstance(item, dict)
                and item.get("port") == inbound_port]
    if len(selected) != 1:
        raise XhttpRouteHold("KH_XHTTP_INBOUND_NOT_UNIQUE")
    inbound = selected[0]
    path = inbound.get("path")
    if (inbound.get("listen") != "127.0.0.1"
            or inbound.get("protocol") != "vless"
            or inbound.get("network") != "xhttp"
            or inbound.get("enabled") is not True
            or not isinstance(path, str)):
        raise XhttpRouteHold("KH_XHTTP_INBOUND_UNAPPROVED")

    # Digest only the selected, sanitized evidence. Unrelated ports do not
    # invalidate an already approved per-child route grant.
    owner_facts = {
        "tunnel_id": owner.id,
        "control_port": 7000,
        "proxy_port": lease.remote_port,
    }
    inbound_facts = {
        "port": inbound_port, "listen": inbound["listen"],
        "protocol": inbound["protocol"], "network": inbound["network"],
        "path": path, "enabled": True,
    }
    binding = ApprovedRouteBinding(
        ir_node=ir.id, kh_node=kh.id, owner=owner.id, child=child.id,
        lease=lease.tunnel_id, port=inbound_port, path=path,
        owner_proof_sha256=_canonical_hash(owner_facts),
        kh_inventory_sha256=_canonical_hash(inbound_facts),
    )
    try:
        wire = sign_route_intent(
            binding, dedicated_broker_key=_broker_key(), now=now,
        )
    except RouteIntentHold as exc:
        raise XhttpRouteHold("ROUTE_INTENT_REJECTED") from exc

    response = await client.forward_uopti_xhttp_route(ir.id, wire)
    if not isinstance(response, dict) or response.get("status") != "success":
        raise XhttpRouteHold("BROKER_ROUTE_RESULT_UNCONFIRMED")
    return {"status": "success", "result": "route_registered"}


async def list_child_xhttp_inbounds(*, db, tunnel_id: str, client) -> list[dict]:
    """Return sanitized inbound choices for the existing FRP child workflow."""
    result = await db.execute(select(Tunnel).where(Tunnel.id == tunnel_id))
    child = result.scalar_one_or_none()
    if (child is None or child.core != "frp" or child.status != "active"
            or not is_shared_child(child.spec or {})):
        raise XhttpRouteHold("ACTIVE_SHARED_FRP_CHILD_REQUIRED")
    lease_result = await db.execute(select(FrpProxyLease).where(
        FrpProxyLease.tunnel_id == child.id
    ))
    lease = lease_result.scalar_one_or_none()
    if (lease is None or lease.iran_node_id != (child.iran_node_id or child.node_id)
            or lease.foreign_node_id != child.foreign_node_id
            or lease.owner_tunnel_id != child.spec.get("shared_frps_owner")):
        raise XhttpRouteHold("ACTIVE_UNIQUE_LEASE_MISMATCH")
    response = await client.get_signed_sanaei_xhttp_inbounds(lease.foreign_node_id)
    inbounds = (response.get("inbounds") if isinstance(response, dict)
                and response.get("status") == "success"
                and response.get("schema_version") == 1 else None)
    if not isinstance(inbounds, list):
        raise XhttpRouteHold("SIGNED_KH_INVENTORY_UNAVAILABLE")
    choices = []
    for item in inbounds:
        if (not isinstance(item, dict) or type(item.get("port")) is not int
                or item.get("listen") != "127.0.0.1"
                or item.get("protocol") != "vless"
                or item.get("network") != "xhttp"
                or item.get("enabled") is not True
                or not isinstance(item.get("path"), str)):
            raise XhttpRouteHold("KH_XHTTP_INBOUND_UNAPPROVED")
        if item["port"] == lease.remote_port:
            choices.append({"port": item["port"], "path": item["path"]})
    return choices
