"""Agent API endpoints"""
from fastapi import APIRouter, Request, HTTPException, Depends
from app.agent_auth import require_agent_auth
from pydantic import BaseModel
from typing import Dict, Any
import logging

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


@router.post("/tunnels/apply")
async def apply_tunnel(data: TunnelApply, request: Request):
    """Apply tunnel configuration"""
    logger = logging.getLogger(__name__)
    adapter_manager = request.app.state.adapter_manager
    
    logger.info(f"Applying tunnel {data.tunnel_id}: core={data.core}, type={data.type}")
    try:
        await adapter_manager.apply_tunnel(
            tunnel_id=data.tunnel_id,
            tunnel_core=data.core,
            spec=data.spec
        )
        logger.info(f"Tunnel {data.tunnel_id} applied successfully")
        return {"status": "success", "message": "Tunnel applied"}
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

