"""Staged Smite Node enrollment HTTP endpoints; disabled until rollout.

The issuing endpoint REQUIRES authenticated administrator JWT.
The redemption endpoint is one-shot code based and requires an unguessable
ingress proof header injected by *trusted HTTPS/443 Nginx*, not by the Node.
Never enable before Nginx, TLS and Node client integration are reviewed.
"""
from __future__ import annotations

import hmac
import sqlite3

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.config import settings
from app.models import Admin
from app.routers import auth
from app import node_pairing_store as pairing


router = APIRouter()

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


def _http_error(status_code: int, detail: str) -> HTTPException:
    # FastAPI drops the injected Response object when an exception is raised.
    return HTTPException(status_code=status_code, detail=detail, headers=_NO_STORE_HEADERS)



class PairingIssueRequest(BaseModel):
    node_id: str = Field(min_length=8, max_length=80)
    role: str
    ttl_seconds: int = Field(default=600, ge=60, le=900)


class PairingCodeResponse(BaseModel):
    node_id: str
    pairing_code: str
    expires_at: int


class PairingRedeemRequest(BaseModel):
    node_id: str = Field(min_length=8, max_length=80)
    role: str
    pairing_code: str = Field(min_length=15, max_length=128)


class PairingCredentialResponse(BaseModel):
    node_id: str
    node_secret: str


def _database_path() -> str:
    if settings.db_type != "sqlite":
        raise _http_error(status_code=503, detail="Node pairing database unavailable")
    return settings.db_path


def _require_preview() -> bytes:
    if not settings.smite_node_pairing_preview_enabled:
        raise _http_error(status_code=503, detail="Node pairing is not enabled")
    master = settings.smite_node_pairing_master_key
    ingress = settings.smite_node_pairing_ingress_token
    # Fail closed: a valid Fernet key is checked by pairing._fernet.
    if not master or not ingress or len(ingress) < 32:
        raise _http_error(status_code=503, detail="Node pairing is not configured")
    try:
        pairing._fernet(master)
    except pairing.PairingDenied as exc:
        raise _http_error(status_code=503, detail="Node pairing is not configured") from exc
    return master.encode("ascii")


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"


@router.post("/issue", response_model=PairingCodeResponse)
async def issue_code(
    request: PairingIssueRequest,
    response: Response,
    admin: Admin = Depends(auth.get_current_user),
):
    """Admin-approved, scoped code. Shown ONCE: do not copy to logs."""
    _no_store(response)
    master = _require_preview()
    try:
        result = await run_in_threadpool(
            pairing.issue_code, _database_path(),
            master_key=master, node_id=request.node_id, role=request.role,
            admin_id=admin.id, ttl_seconds=request.ttl_seconds,
        )
    except pairing.PairingDenied as exc:
        raise _http_error(status_code=409, detail="Pairing approval denied") from exc
    except sqlite3.Error as exc:
        raise _http_error(status_code=503, detail="Pairing database unavailable") from exc
    return PairingCodeResponse(
        node_id=result.node_id, pairing_code=result.code,
        expires_at=result.expires_at,
    )


@router.post("/redeem", response_model=PairingCredentialResponse)
async def redeem_code(
    request: PairingRedeemRequest,
    response: Response,
    x_smite_pairing_ingress: str = Header(default="", alias="X-Smite-Pairing-Ingress"),
):
    """One-time enrollment over verified 443 gateway.

    Nginx must STRIP any client-supplied X-Smite-Pairing-Ingress and SET its
    own server-side header to the ingress secret. Direct backend requests
    and gateways without the proof are rejected. No proxy TLS header
    like X-Forwarded-Proto is trusted here.
    """
    _no_store(response)
    master = _require_preview()
    expected = settings.smite_node_pairing_ingress_token
    if not hmac.compare_digest(x_smite_pairing_ingress, expected):
        raise _http_error(status_code=403, detail="Pairing ingress rejected")
    try:
        credential = await run_in_threadpool(
            pairing.redeem_code, _database_path(), master_key=master,
            code=request.pairing_code, node_id=request.node_id,
            role=request.role,
        )
    except pairing.PairingDenied as exc:
        raise _http_error(status_code=403, detail="Pairing denied") from exc
    except sqlite3.Error as exc:
        raise _http_error(status_code=503, detail="Pairing database unavailable") from exc
    return PairingCredentialResponse(
        node_id=credential.node_id, node_secret=credential.secret,
    )
