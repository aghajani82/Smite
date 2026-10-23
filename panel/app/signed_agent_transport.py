"""Authenticated Panel->Agent request transport (opt-in, no legacy fallback).

The legacy Node registry is not a trustworthy source of secrets. The private
per-node secret is looked up exclusively from the pairing identity database,
never from untrusted Node.metadata, /api/nodes, browser JWTs or FRP tokens.

HTTPS uses public-CA hostname verification and port 443 only. HTTP is allowed
only to *literal* 127.0.0.1, either fixed local Node port 8888 or an explicitly
selected local FRP transport. The caller must preserve the signed exact target
and bytes; any proxy rewriting that path breaks authentication (fail closed).
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
import re
from urllib.parse import urlsplit

import httpx
from starlette.concurrency import run_in_threadpool

from app.agent_request_signer import prepare_agent_request
from app.config import settings
from app import node_pairing_store


_DOMAIN = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class SignedAgentUnavailable(RuntimeError):
    """Generic failure. Never echo credentials or URLs in public responses."""


def validate_agent_origin(address: str, *, using_frp: bool) -> str:
    """Normalize and refuse proxy/redirect/cleartext WAN endpoints."""
    if not isinstance(address, str) or any(ch.isspace() for ch in address):
        raise SignedAgentUnavailable("Signed Node endpoint not permitted")
    try:
        parts = urlsplit(address)
        hostname = parts.hostname
        port = parts.port
    except (ValueError, TypeError) as exc:
        raise SignedAgentUnavailable("Signed Node endpoint not permitted") from exc

    if (
        not hostname or parts.username is not None or parts.password is not None
        or parts.path not in ("", "/") or parts.query or parts.fragment
    ):
        raise SignedAgentUnavailable("Signed Node endpoint not permitted")

    if parts.scheme == "http":
        if hostname != "127.0.0.1":
            raise SignedAgentUnavailable("Plain HTTP to a remote Node is prohibited")
        # FRP must be explicitly chosen by upstream address resolver. Only
        # local Node may use 8888 when not inside FRP.
        if port is None or not (1 <= port <= 65535):
            raise SignedAgentUnavailable("Explicit loopback port required")
        if not using_frp and port != 8888:
            raise SignedAgentUnavailable("Unapproved localhost port")
        return f"http://127.0.0.1:{port}"

    if parts.scheme == "https" and not using_frp:
        if port not in (None, 443):
            raise SignedAgentUnavailable("TLS Node gateway must use port 443")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise SignedAgentUnavailable("TLS identity requires a DNS hostname")
        if not _DOMAIN.fullmatch(hostname.lower()):
            raise SignedAgentUnavailable("TLS Node gateway hostname not approved")
        return f"https://{hostname.lower()}:443"

    raise SignedAgentUnavailable("Node gateway transport prohibited")


def validate_foreign_gateway_prefix(*, origin: str, control_url: str) -> str:
    """Require exact, separately administrator-approved KH 443 path.

    The public gateway strips this prefix before forwarding to the Node, so
    the HMAC target stays the Node's original /api/agent/* raw path.
    """
    normalized = validate_agent_origin(origin, using_frp=False)
    if not normalized.startswith("https://"):
        raise SignedAgentUnavailable("Foreign gateway requires HTTPS/443")
    if not isinstance(control_url, str) or any(ch.isspace() for ch in control_url):
        raise SignedAgentUnavailable("Foreign gateway control path untrusted")
    try:
        parts = urlsplit(control_url)
        host, port = parts.hostname, parts.port
    except (TypeError, ValueError) as exc:
        raise SignedAgentUnavailable("Foreign gateway control URL invalid") from exc
    if (
        parts.scheme != "https" or not host or port not in (None, 443)
        or parts.username is not None or parts.password is not None
        or parts.query or parts.fragment
        or f"https://{host.lower()}:443" != normalized
        or re.fullmatch(r"/smite-node/[A-Za-z0-9_-]{16,80}", parts.path) is None
    ):
        raise SignedAgentUnavailable("Foreign gateway control URL not approved")
    return normalized + parts.path


def get_paired_key(*, node_id: str) -> bytes:
    """Read one active, unrevoked per-node key without creating a database."""
    if not settings.smite_node_pairing_master_key:
        raise SignedAgentUnavailable("Node pairing master is unavailable")
    if settings.db_type != "sqlite":
        raise SignedAgentUnavailable("Node pairing database unavailable")
    try:
        db = Path(settings.db_path)
        if not db.is_file():
            raise SignedAgentUnavailable("Node pairing database unavailable")
        return node_pairing_store.get_active_secret(
            db, master_key=settings.smite_node_pairing_master_key, node_id=node_id
        )
    except (OSError, ValueError, node_pairing_store.PairingDenied) as exc:
        raise SignedAgentUnavailable("Paired Node identity is missing or invalid") from exc


async def signed_agent_call(
    *, node_id: str, address: str, using_frp: bool,
    method: str, target: str, payload: dict | None = None,
    timeout: float = 30.0,
    gateway_control_url: str | None = None,
) -> dict:
    """Send ONE signed request. No redirect, no insecure TLS, no old fallback.

    Retrying Apply/Remove automatically would be unsafe without request-id
    reconciliation: a server may have applied a command whose response was
    lost. Caller must query current status before repeating a command.
    """
    origin = validate_agent_origin(address, using_frp=using_frp)
    # Only an explicit, protected, independently approved foreign control path
    # may be used. Never derive this prefix from Node registration metadata.
    wire_base = (
        validate_foreign_gateway_prefix(
            origin=origin, control_url=gateway_control_url,
        )
        if gateway_control_url is not None else origin
    )
    secret = await run_in_threadpool(get_paired_key, node_id=node_id)
    body, signed_headers = prepare_agent_request(
        secret=secret, node_id=node_id, method=method,
        target=target, payload=payload,
    )
    url = wire_base + target
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            verify=True,
            trust_env=False,
            follow_redirects=False,
            limits=httpx.Limits(max_keepalive_connections=0),
        ) as client:
            response = await client.request(
                method, url, content=body, headers=signed_headers
            )
        if response.is_redirect:
            raise SignedAgentUnavailable("Node gateway redirected signed request")
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise SignedAgentUnavailable("Unexpected Node response")
        return data
    except (httpx.HTTPError, ValueError) as exc:
        raise SignedAgentUnavailable("Signed Node request failed") from exc
