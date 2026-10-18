"""Build exact, signed Panel->Agent HTTP requests (standalone migration helper).

NOT automatically wired into the legacy NodeClient yet. Do not sign an HTTP
request and then resend it via json=... (different bytes invalidate HMAC).
The caller MUST send the returned byte string unchanged via content=body.
"""
from __future__ import annotations

import json
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
    # This migration helper accepts exact fixed paths only. A separate
    # future helper will canonicalize + sign status query strings.
    if (
        split.scheme or split.netloc or split.query or split.fragment
        or split.path not in ALLOWED_AGENT_TARGETS
        or target != split.path
    ):
        raise AgentRequestPreparationError("Unapproved Agent target")


def prepare_agent_request(
    *, secret: bytes | str, node_id: str, method: str,
    target: str, payload: dict[str, Any] | None = None,
    timestamp: int | None = None, nonce: str | None = None,
) -> tuple[bytes, dict[str, str]]:
    """Return exact wire body + signed headers for a scoped Agent request."""
    _target_check(target)
    if (method, target) not in (
        ("POST", "/api/agent/tunnels/apply"),
        ("POST", "/api/agent/tunnels/remove"),
        ("GET", "/api/agent/status"),
        ("GET", "/api/agent/tunnels/status"),
    ):
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
