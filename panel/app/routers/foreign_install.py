"""Trial-only Foreign installation APIs; disabled by default.

Admin JWT/MFA authorizes issuing/revoking grants. Redemption requires the
existing trusted TLS gateway proof AND a scoped one-use grant. No network calls,
origin-file writes, schema migrations or Node activation happen in these routes.
"""
from __future__ import annotations

import hmac
from pathlib import Path
import sqlite3

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.models import Admin
from app.routers import auth, node_pairing
from app import foreign_install_grants as grants
from app import node_pairing_store as pairing

HEADERS = {
    'Cache-Control': 'no-store', 'Pragma': 'no-cache',
    'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
}


class PrivateRoute(APIRoute):
    """Never echo validation inputs (which contain enrollment credentials)."""
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def private(request: Request):
            try:
                # Bound streamed bodies before FastAPI parses JSON, including
                # chunked requests without a Content-Length header.
                body = bytearray()
                async for chunk in request.stream():
                    if len(body) + len(chunk) > 8192:
                        return JSONResponse({'detail': 'Request too large'}, status_code=413, headers=HEADERS)
                    body.extend(chunk)
                request._body = bytes(body)
                response = await handler(request)
            except RequestValidationError:
                return JSONResponse({'detail': 'Invalid installation request'}, status_code=422, headers=HEADERS)
            except StarletteHTTPException as exc:
                # Do not reflect dependency exception bodies or tokens.
                return JSONResponse({'detail': 'Installation request rejected'}, status_code=exc.status_code, headers=HEADERS)
            except (sqlite3.Error, OSError):
                return JSONResponse({'detail': 'Installation service unavailable'}, status_code=503, headers=HEADERS)
            response.headers.update(HEADERS)
            return response
        return private


router = APIRouter(route_class=PrivateRoute)


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class IssueRequest(StrictRequest):
    node_id: str = Field(min_length=8, max_length=80, pattern=r'^[A-Za-z0-9_-]+$')
    node_name: str = Field(min_length=2, max_length=64, pattern=r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')
    domain: str = Field(min_length=4, max_length=253)
    ttl_seconds: int = Field(default=grants.DEFAULT_TTL, ge=60, le=grants.MAX_TTL)


class RevokeRequest(StrictRequest):
    node_id: str = Field(min_length=8, max_length=80, pattern=r'^[A-Za-z0-9_-]+$')


class RedeemRequest(RevokeRequest):
    node_name: str = Field(min_length=2, max_length=64)
    control_url: str = Field(min_length=10, max_length=400)
    installation_code: SecretStr
    node_secret: SecretStr

    @field_validator('installation_code')
    @classmethod
    def code_format(cls, value):
        if not grants._CODE.fullmatch(value.get_secret_value()):
            raise ValueError('Invalid credential')
        return value

    @field_validator('node_secret')
    @classmethod
    def secret_format(cls, value):
        if not grants._SECRET.fullmatch(value.get_secret_value()):
            raise ValueError('Invalid credential')
        return value


def schema_ready() -> bool:
    """Read only; absent DB/schema is never silently created or migrated."""
    path = Path(settings.db_path)
    if settings.db_type != 'sqlite' or path.is_symlink() or not path.is_file():
        return False
    try:
        with sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=2) as conn:
            for query in (
                'SELECT id,name,metadata FROM nodes LIMIT 0',
                'SELECT node_id,node_role,encrypted_secret,paired_at,revoked_at FROM smite_node_identities LIMIT 0',
                'SELECT code_hash,node_id,consumed_at FROM smite_node_pairing_codes LIMIT 0',
                'SELECT code_hash,node_id,node_name,origin,control_url,issued_by,issued_at,expires_at,consumed_at,revoked_at FROM smite_foreign_install_grants LIMIT 0',
                'SELECT node_id,node_name,origin,control_url,grant_hash,approved_at FROM smite_foreign_install_origins LIMIT 0',
            ):
                conn.execute(query)
        return True
    except (sqlite3.Error, OSError):
        return False


async def require_installation() -> bytes:
    if (not settings.smite_foreign_install_enabled
            or settings.smite_node_registration_mode != 'signed'
            or settings.smite_panel_agent_auth_mode != 'signed'):
        raise HTTPException(503)
    master = node_pairing._require_preview()
    if not await run_in_threadpool(schema_ready):
        raise HTTPException(503)
    return master


@router.get('/capabilities')
async def capabilities(admin: Admin = Depends(auth.get_current_user)):
    try:
        await require_installation()
        ready = True
    except HTTPException:
        ready = False
    return {'foreign_install_enabled': ready, 'default_ttl_seconds': grants.DEFAULT_TTL,
            'max_ttl_seconds': grants.MAX_TTL, 'protocol': 'smi1'}


@router.post('/issue')
async def issue(request: IssueRequest, admin: Admin = Depends(auth.get_current_user)):
    master = await require_installation()
    try:
        grant = await run_in_threadpool(grants.issue, settings.db_path,
            master_key=master, admin_id=admin.id, node_id=request.node_id,
            node_name=request.node_name, domain=request.domain,
            ttl_seconds=request.ttl_seconds)
    except pairing.PairingDenied as exc:
        raise HTTPException(409) from exc
    return {'node_id': grant.node_id, 'node_name': grant.node_name,
            'origin': grant.origin, 'control_url': grant.control_url,
            'installation_code': grant.code, 'expires_at': grant.expires_at}


@router.post('/revoke')
async def revoke(request: RevokeRequest, admin: Admin = Depends(auth.get_current_user)):
    await require_installation()
    await run_in_threadpool(grants.revoke_pending, settings.db_path, node_id=request.node_id)
    return {'status': 'revoked'}


@router.post('/redeem')
async def redeem(request: RedeemRequest,
                 ingress: str = Header(default='', alias='X-Smite-Pairing-Ingress')):
    master = await require_installation()
    expected = settings.smite_node_pairing_ingress_token
    # Header value must be set by a trusted local TLS/443 gateway, stripping
    # client-supplied values. Ordinary proxy X-Forwarded-Proto is not evidence.
    if not hmac.compare_digest(ingress.encode('utf-8'), expected.encode('utf-8')):
        raise HTTPException(403)
    try:
        await run_in_threadpool(grants.redeem, settings.db_path,
            master_key=master, code=request.installation_code.get_secret_value(),
            node_id=request.node_id, node_name=request.node_name,
            control_url=request.control_url, node_secret=request.node_secret.get_secret_value())
    except pairing.PairingDenied as exc:
        raise HTTPException(403) from exc
    return {'status': 'enrolled', 'node_id': request.node_id}
