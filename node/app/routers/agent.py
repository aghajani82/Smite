"""Agent API endpoints"""
from fastapi import APIRouter, Request, HTTPException, Depends
from app.agent_auth import require_agent_auth
from app.engine_inventory import engine_inventory, require_engine_ready, EngineInventoryUnavailable
from pydantic import BaseModel
from typing import Dict, Any
import logging
from starlette.concurrency import run_in_threadpool

# Strict mode gates status AND Apply/Remove without route-level bypass.
# Default legacy mode intentionally preserves current Node interoperability.
router = APIRouter(dependencies=[Depends(require_agent_auth)])
logger = logging.getLogger(__name__)



class TunnelApply(BaseModel):
    tunnel_id: str
    core: str
    type: str
    spec: Dict[str, Any]


class TunnelRemove(BaseModel):
    tunnel_id: str


class UoptiRouteIntent(BaseModel):
    intent_b64: str


@router.post("/tunnels/apply")
async def apply_tunnel(data: TunnelApply, request: Request):
    """Apply tunnel configuration"""
    logger = logging.getLogger(__name__)
    adapter_manager = request.app.state.adapter_manager
    
    logger.info(f"Applying tunnel {data.tunnel_id}: core={data.core}, type={data.type}")
    try:
        # In the new Core-only installation no tunnel engine is enrolled.
        # Refuse Apply before touching config, Docker, binaries or adapters.
        try:
            require_engine_ready(data.core)
        except EngineInventoryUnavailable:
            raise HTTPException(409, detail="Selected tunnel engine is not ready")
        await adapter_manager.apply_tunnel(
            tunnel_id=data.tunnel_id,
            tunnel_core=data.core,
            spec=data.spec
        )
        logger.info(f"Tunnel {data.tunnel_id} applied successfully")
        return {"status": "success", "message": "Tunnel applied"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to apply tunnel {data.tunnel_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tunnels/remove")
async def remove_tunnel(data: TunnelRemove, request: Request):
    """Remove tunnel"""
    adapter_manager = request.app.state.adapter_manager
    
    try:
        await adapter_manager.remove_tunnel(data.tunnel_id)
        return {"status": "success", "message": "Tunnel removed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tunnels/status")
async def get_tunnel_status(tunnel_id: str, request: Request):
    """Get tunnel status"""
    adapter_manager = request.app.state.adapter_manager
    
    try:
        status = await adapter_manager.get_tunnel_status(tunnel_id)
        return {"status": "success", "data": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_status(request: Request):
    """Get node status"""
    adapter_manager = request.app.state.adapter_manager
    
    return {
        "status": "ok",
        "active_tunnels": len(adapter_manager.active_tunnels),
        "tunnels": list(adapter_manager.active_tunnels.keys())
    }


@router.get("/frp/owners")
async def signed_frps_owners(request: Request):
    """Read-only, auth-required proof of the ONE local FRPS owner."""
    from app.config import settings
    from app.frp_owner_status import active_signed_frps_owners
    if settings.smite_agent_auth_mode != "strict":
        # Not a legacy HMAC or anonymous discovery API.
        raise HTTPException(409, detail="Signed FRPS owner evidence unavailable")
    owners = active_signed_frps_owners(request.app.state.adapter_manager)
    return {"status": "success", "owners": owners}


@router.get("/inbounds/xhttp")
async def get_signed_xhttp_inbounds():
    """KH-only, explicit opt-in, read-only, no identifiers or client secrets."""
    from app.config import settings
    from app.sanaei_inbound_inventory import (
        list_approved_xhttp_inbounds, SanaeiInventoryUnavailable,
    )
    if (settings.smite_agent_auth_mode != "strict"
            or settings.node_role != "foreign"
            or not settings.smite_sanaei_inventory_enabled):
        raise HTTPException(409, detail="Signed Sanaei inventory unavailable")
    try:
        items = list_approved_xhttp_inbounds(settings.smite_sanaei_db_path)
    except SanaeiInventoryUnavailable as exc:
        raise HTTPException(503, detail="Sanaei inventory unavailable") from exc
    return {"status": "success", "schema_version": 1, "inbounds": items}


class ApprovalEvidenceQuery(BaseModel):
    kind: str
    port: int


@router.post("/approval/evidence")
async def signed_independent_approval_evidence(data: ApprovalEvidenceQuery, request: Request):
    """Opt-in, strictly signed, READ ONLY Node evidence for independent Root.

    The Panel may request facts but cannot forge the independently signed
    response without the Node's dedicated root-owned Ed25519 private key.
    No FRPS/FRPC/config mutation, route grant or database write occurs.
    """
    from app.config import settings
    from app.approval_runtime_evidence import collect, RuntimeAttestationHold
    if settings.smite_agent_auth_mode != "strict":
        raise HTTPException(409, detail="Independent attestation unavailable")
    try:
        return {"status":"success","attestation":await run_in_threadpool(
            collect, kind=data.kind, port=data.port, settings=settings,
            adapter_manager=request.app.state.adapter_manager,
        )}
    except RuntimeAttestationHold as exc:
        raise HTTPException(409, detail="Independent runtime evidence HOLD") from exc


@router.post("/uopti/xhttp-route")
async def forward_uopti_xhttp_route(data: UoptiRouteIntent):
    """Forward one Panel-signed intent to the local root broker over UDS."""
    from app.config import settings
    from app.uopti_route_broker_client import (
        BrokerForwardUnavailable, BrokerRootGrantRequired,
        decode_intent_b64, forward_route_intent,
    )
    if (settings.smite_agent_auth_mode != "strict"
            or settings.node_role != "iran"
            or not settings.smite_uopti_route_broker_enabled):
        raise HTTPException(409, detail="U-OPTI route broker unavailable")
    try:
        wire = decode_intent_b64(data.intent_b64)
        await run_in_threadpool(
            forward_route_intent, wire, settings.smite_uopti_route_broker_socket,
        )
    except BrokerRootGrantRequired as exc:
        # This exact response is emitted only before nonce consumption or
        # route mutation; it safely directs the operator to the separate
        # root-only per-child approval command.
        raise HTTPException(409, detail="ROOT_OPERATOR_GRANT_REQUIRED") from exc
    except BrokerForwardUnavailable as exc:
        # Do not expose broker internals or retry an ambiguous host transaction.
        raise HTTPException(503, detail="U-OPTI route broker HOLD") from exc
    return {"status": "success", "result": "route_added"}


@router.get("/engines")
async def get_engines():
    """Authenticated, read-only engine availability; never installs anything."""
    try:
        return engine_inventory()
    except EngineInventoryUnavailable as exc:
        raise HTTPException(503, detail="Engine inventory unavailable") from exc
