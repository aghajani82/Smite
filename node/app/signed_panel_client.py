"""Strict opt-in Node->Panel signed status and registration client.

Never sends the pairing key/code on the wire. Never uses legacy verify=False.
Accepts DNS hostname HTTPS/443 ONLY, rejects redirects, HTTPS proxies and
unverified certificates. No automatic retry for ambiguous state changes.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

import httpx
from starlette.concurrency import run_in_threadpool

from app.agent_auth import read_identity, AgentAuthUnavailable
from app.config import settings
from app.node_auth import sign_request


_HOST = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_TARGETS = frozenset(("/api/node-control/register", "/api/node-control/frp-status"))


class SignedPanelUnavailable(RuntimeError):
    pass


def validated_panel_origin(address: str) -> str:
    """Supports the existing domain:443 and https://domain:443 formats."""
    if not isinstance(address, str) or any(x.isspace() for x in address):
        raise SignedPanelUnavailable("Panel HTTPS/443 origin required")
    value = address if "://" in address else "https://" + address
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise SignedPanelUnavailable("Invalid Panel HTTPS origin") from exc
    if (
        parsed.scheme != "https" or not host
        or parsed.username is not None or parsed.password is not None
        or port not in (None, 443)
        or parsed.path not in ("", "/") or parsed.query or parsed.fragment
        or not _HOST.fullmatch(host.lower())
    ):
        raise SignedPanelUnavailable("Panel must be a DNS hostname over HTTPS/443")
    return f"https://{host.lower()}:443"


async def signed_panel_post(*, target: str, data: dict) -> dict:
    """Sign exactly the raw bytes transmitted; never use json=data afterwards."""
    if target not in _TARGETS or not isinstance(data, dict):
        raise SignedPanelUnavailable("Unexpected Panel control target")
    origin = validated_panel_origin(settings.panel_address)
    try:
        node_id, secret = await run_in_threadpool(
            read_identity, settings.smite_agent_identity_path
        )
    except AgentAuthUnavailable as exc:
        raise SignedPanelUnavailable("Node pairing identity unavailable") from exc
    if data.get("node_id") != node_id:
        raise SignedPanelUnavailable("Identity mismatch")
    try:
        payload = json.dumps(
            data, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        headers = sign_request(
            secret=secret, node_id=node_id, method="POST",
            target=target, body=payload,
        )
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json"
        headers["Cache-Control"] = "no-store"
        async with httpx.AsyncClient(
            verify=True, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(12.0),
        ) as client:
            response = await client.post(origin + target, content=payload, headers=headers)
        if response.is_redirect:
            raise SignedPanelUnavailable("Panel redirect rejected")
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise SignedPanelUnavailable("Invalid Panel reply")
        return result
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise SignedPanelUnavailable("Signed Panel control request failed") from exc


async def signed_register() -> dict:
    node_id, _ = await run_in_threadpool(
        read_identity, settings.smite_agent_identity_path
    )
    return await signed_panel_post(
        target="/api/node-control/register",
        data={"node_id": node_id, "role": settings.node_role},
    )


async def signed_frp_status(*, connected: bool, remote_port: int | None) -> dict:
    node_id, _ = await run_in_threadpool(
        read_identity, settings.smite_agent_identity_path
    )
    return await signed_panel_post(
        target="/api/node-control/frp-status",
        data={"node_id": node_id, "connected": connected, "remote_port": remote_port},
    )
