"""Opt-in machine-only signed registry, separate from legacy /api/nodes.

Only paired existing Node UUIDs may check in; no creation, no reassignment
of role/IP/address, and no arbitrary metadata override. Does not replace
administrator Node enrollment. TLS/443 termination must be verified end to end.
"""
from __future__ import annotations

from datetime import datetime
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.database import get_db
from app.models import Node, Settings
from app.config import settings
from app.node_client import NodeClient
from app.signed_node_origins import approved_node, control_url_matches, ApprovedOriginUnavailable
from app.signed_node_registration import authenticated_node


router = APIRouter()
_HOST = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class Checkin(BaseModel):
    node_id: str = Field(min_length=8, max_length=80)
    role: str


class GatewayCheck(BaseModel):
    node_id: str = Field(min_length=8, max_length=80)
    node_name: str = Field(min_length=1, max_length=128)
    control_url: str = Field(min_length=10, max_length=512)


class FrpHeartbeat(BaseModel):
    node_id: str = Field(min_length=8, max_length=80)
    connected: bool
    remote_port: int | None = Field(default=None, ge=1, le=65535)


def _no_store(response: Response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _decode(model, raw: bytes):
    try:
        return model.model_validate_json(raw)
    except ValidationError as exc:
        raise HTTPException(422, detail="Invalid Node report") from exc


async def _find_node(node_id: str, db: AsyncSession) -> Node:
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if node is None:
        raise HTTPException(403, detail="Unauthorized Node")
    return node


def _role_matches(node: Node, role: str) -> bool:
    role_in_db = (node.node_metadata or {}).get("role")
    return role in ("iran", "foreign") and role == role_in_db


@router.post("/register")
async def signed_checkin(
    response: Response,
    authenticated: tuple[str, bytes] = Depends(authenticated_node),
    db: AsyncSession = Depends(get_db),
):
    _no_store(response)
    node_id, raw = authenticated
    report = _decode(Checkin, raw)
    if report.node_id != node_id:
        raise HTTPException(403, detail="Unauthorized Node")
    node = await _find_node(node_id, db)
    if not _role_matches(node, report.role):
        raise HTTPException(403, detail="Unauthorized Node")
    # Only authenticated HMAC check-in (not admin reservation) clears the
    # operator UI's "Waiting for pairing" marker. A forged legacy POST
    # cannot upgrade a pending Node to signed/paired status.
    if (node.node_metadata or {}).get("provisioning") == "reserved_for_pairing":
        metadata = dict(node.node_metadata or {})
        metadata["provisioning"] = "signed_checkin"
        node.node_metadata = metadata
        flag_modified(node, "node_metadata")
    node.last_seen = datetime.utcnow()
    node.status = "active"
    await db.commit()

    # Signed response over verified TLS. Never pull FRP endpoint from a
    # self-asserted Node-supplied address as the legacy route currently does.
    meta = {}
    result = await db.execute(select(Settings).where(Settings.key == "frp"))
    frp = result.scalar_one_or_none()
    if frp is not None and frp.value and frp.value.get("enabled"):
        host = (settings.panel_domain or "").strip().lower()
        if not _HOST.fullmatch(host):
            raise HTTPException(
                503, detail="Panel FRP host must be configured before signed registration"
            )
        token = frp.value.get("token")
        port = frp.value.get("port", 7000)
        if not isinstance(token, str) or not token or not isinstance(port, int) or not 1 <= port <= 65535:
            raise HTTPException(503, detail="Panel FRP configuration unavailable")
        meta["frp_config"] = {
            "enabled": True, "server_addr": host,
            "server_port": port, "token": token,
        }
    return {"id": node.id, "status": "active", "metadata": meta}


@router.post("/gateway-check")
async def signed_gateway_check(
    response: Response,
    authenticated: tuple[str, bytes] = Depends(authenticated_node),
    db: AsyncSession = Depends(get_db),
):
    """Answer only whether the caller's OWN registered Node is reachable.

    This replaces KH U-OPTI's anonymous GET /api/nodes enumeration. Never
    include Node listings, addresses, FRP config or keys in this response.
    Strict paired identity AND signed Panel->Node status are both required.
    """
    _no_store(response)
    if (
        settings.smite_node_registration_mode != "signed"
        or settings.smite_panel_agent_auth_mode != "signed"
    ):
        raise HTTPException(503, detail="Signed gateway readiness unavailable")
    node_id, raw = authenticated
    report = _decode(GatewayCheck, raw)
    if report.node_id != node_id:
        raise HTTPException(403, detail="Unauthorized Node")
    node = await _find_node(node_id, db)
    meta = node.node_metadata or {}
    try:
        pin = approved_node(node_id)
    except ApprovedOriginUnavailable:
        # Do not disclose whether an origin exists or who approved it.
        return {"status": "ok", "gateway_ready": False}
    if (
        pin["role"] != "foreign"
        or meta.get("role") != "foreign"
        or pin["node_name"] != report.node_name
        or (node.name != report.node_name and meta.get("node_name") != report.node_name)
        or not control_url_matches(pin, report.control_url)
    ):
        return {"status": "ok", "gateway_ready": False}
    try:
        result = await NodeClient().get_tunnel_status(node.id)
        active = isinstance(result, dict) and result.get("status") == "ok"
    except Exception:
        active = False
    return {"status": "ok", "gateway_ready": active}


@router.post("/frp-status")
async def signed_frp_status(
    response: Response,
    authenticated: tuple[str, bytes] = Depends(authenticated_node),
    db: AsyncSession = Depends(get_db),
):
    _no_store(response)
    node_id, raw = authenticated
    report = _decode(FrpHeartbeat, raw)
    if report.node_id != node_id or (report.connected and report.remote_port is None):
        raise HTTPException(403, detail="Unauthorized Node")
    node = await _find_node(node_id, db)
    metadata = dict(node.node_metadata or {})
    if not _role_matches(node, metadata.get("role", "")):
        raise HTTPException(403, detail="Unauthorized Node")
    metadata["frp_connected"] = report.connected
    if report.connected:
        metadata["frp_remote_port"] = report.remote_port
    else:
        metadata.pop("frp_remote_port", None)
    node.node_metadata = metadata
    flag_modified(node, "node_metadata")
    node.last_seen = datetime.utcnow()
    await db.commit()
    return {"status": "success"}
