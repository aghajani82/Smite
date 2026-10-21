"""Loopback-only process readiness probe for Docker.

Do NOT reuse the authenticated Agent status endpoint as a Docker healthcheck:
in managed strict mode the Agent requires a signed, nonce-bearing HMAC.
This deliberately narrow, unlisted local probe never exposes inventory,
tunnels, identity, tokens, settings or replay data.
"""
from ipaddress import ip_address
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.get("/healthz", include_in_schema=False)
async def local_health(request: Request) -> dict[str, str]:
    # Trust the actual TCP socket peer, never X-Forwarded-For headers.
    peer = request.client.host if request.client is not None else ""
    try:
        loopback = ip_address(peer).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise HTTPException(status_code=403, detail="Local healthcheck only")

    # The ASGI listener may start before lifespan initializes the adapter
    # manager. Mark the container healthy only after Node startup completes.
    if getattr(request.app.state, "adapter_manager", None) is None:
        raise HTTPException(status_code=503, detail="Node initialization pending")
    return {"status": "ok"}
