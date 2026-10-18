"""Build exact, signed Panel->Agent HTTP requests (standalone migration helper).

NOT automatically wired into the legacy NodeClient yet. Do not sign an HTTP
request and then resend it via json=... (different bytes invalidate HMAC).
The caller MUST send the returned byte string unchanged via content=body.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from app import node_auth


ALLOWED_AGENT_TARGETS = frozenset((
    "/api/agent/tunnels/apply",
    "/api/agent/tunnels/remove",
    "/api/agent/status",
    "/api/agent/tunnels/status",
))


class AgentRequestPreparationError(ValueError):
    pass


def _target_check(target: str) -> None:
    if not isinstance(target, str):
        raise AgentRequestPreparationError("Target must be an Agent API path")
    split = urlsplit(target)
    # Exactly one restricted status query is accepted. Never sign arbitrary
    # attacker-supplied raw query strings or unrelated control endpoints.
    is_tunnel_status = split.path == "/api/agent/tunnels/status"
    if (
        split.scheme or split.netloc or split.fragment
        or split.path not in ALLOWED_AGENT_TARGETS
        or (is_tunnel_status and not re.fullmatch(r"tunnel_id=[A-Za-z0-9_-]{1,128}", split.query))
        or (not is_tunnel_status and bool(split.query))
        or (target != split.path + ("?" + split.query if split.query else ""))
    ):
        raise AgentRequestPreparationError("Unapproved Agent target")


def prepare_agent_request(
    *, secret: bytes | str, node_id: str, method: str,
    target: str, payload: dict[str, Any] | None = None,
    timestamp: int | None = None, nonce: str | None = None,
) -> tuple[bytes, dict[str, str]]:
    """Return exact wire body + signed headers for a scoped Agent request."""
    _target_check(target)
    allowed = (
        (method == "POST" and target in (
            "/api/agent/tunnels/apply", "/api/agent/tunnels/remove"
        ))
        or (method == "GET" and (
            target == "/api/agent/status"
            or target.startswith("/api/agent/tunnels/status?tunnel_id=")
        ))
    )
    if not allowed:
        raise AgentRequestPreparationError("Wrong Agent method/target")
    if method == "GET":
        if payload is not None:
            raise AgentRequestPreparationError("GET status has no JSON payload")
        body = b""
    else:
        if not isinstance(payload, dict):
            raise AgentRequestPreparationError("POST requires JSON object")
        body = json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    headers = node_auth.sign_request(
        secret=secret, node_id=node_id, method=method,
        target=target, body=body, timestamp=timestamp, nonce=nonce,
    )
    if method == "POST":
        headers["Content-Type"] = "application/json"
    return body, headers
