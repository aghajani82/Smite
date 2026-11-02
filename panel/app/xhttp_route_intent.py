"""Offline Smite Panel-side XHTTP route-intent issuer (NO network or root ops).

This is a wire-format complement to U-OPTI's offline broker contract.
It does not authorize itself: the Root broker MUST separately validate an
independent trusted grant (owner, child, lease and KH inventory), replay and
runtime socket proof before any host file can change. No API calls here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets


class RouteIntentHold(ValueError):
    pass


AUDIENCE = "u-opti:ir:xhttp-route:v1"
IDENT = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PATH = re.compile(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\Z")


@dataclass(frozen=True)
class ApprovedRouteBinding:
    """A digest-bound declaration, not evidence of signed verification.

    Only the future Panel orchestration gate may construct this after
    confirming active lease, Signed IR owner proof and Signed KH inventory.
    """
    ir_node: str
    kh_node: str
    owner: str
    child: str
    lease: str
    port: int
    path: str
    owner_proof_sha256: str
    kh_inventory_sha256: str


def sign_route_intent(
    binding: ApprovedRouteBinding, *,
    dedicated_broker_key: bytes,
    now: int,
) -> bytes:
    """Issue one 30-second canonical HMAC envelope; no side effects.

    The dedicated broker key must be provisioned separately from the normal
    Signed Agent HMAC secret and must NEVER be embedded in release code.
    """
    if (not isinstance(binding, ApprovedRouteBinding)
            or type(dedicated_broker_key) is not bytes
            or len(dedicated_broker_key) != 32
            or type(now) is not int or not 0 <= now < 2 ** 63 - 30):
        raise RouteIntentHold("BROKER_ISSUER_NOT_PREPARED")
    fields = (
        "ir_node", "kh_node", "owner", "child", "lease",
    )
    if any(type(getattr(binding, f)) is not str
           or not IDENT.fullmatch(getattr(binding, f)) for f in fields):
        raise RouteIntentHold("INVALID_ROUTE_IDENTITY")
    if (type(binding.port) is not int
            or not 1024 <= binding.port <= 65535
            or binding.port == 7000):
        raise RouteIntentHold("UNAPPROVED_PROXY_PORT")
    if (type(binding.path) is not str or len(binding.path) > 128
            or not PATH.fullmatch(binding.path)
            or binding.path.split("/")[1].lower() in {"api", "docs", "redoc", "openapi", "assets", "static", "auth", "login", "admin", "health", "metrics", "sub", "ws"}):
        raise RouteIntentHold("UNAPPROVED_XHTTP_PATH")
    if any(type(getattr(binding, f)) is not str
           or not HEX64.fullmatch(getattr(binding, f))
           for f in ("owner_proof_sha256", "kh_inventory_sha256")):
        raise RouteIntentHold("UNVERIFIED_EVIDENCE_FORMAT")
    nonce = secrets.token_hex(16)
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise RouteIntentHold("SECURE_NONCE_UNAVAILABLE")
    data = {
        "schema": 1,
        "audience": AUDIENCE,
        "action": "create",
        "ir_node": binding.ir_node,
        "kh_node": binding.kh_node,
        "owner": binding.owner,
        "child": binding.child,
        "lease": binding.lease,
        "port": binding.port,
        "path": binding.path,
        "owner_proof_sha256": binding.owner_proof_sha256,
        "kh_inventory_sha256": binding.kh_inventory_sha256,
        "issued_at": now,
        "expires_at": now + 30,
        "nonce": nonce,
    }
    payload = json.dumps(
        data, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    mac = hmac.new(dedicated_broker_key, payload, hashlib.sha256).hexdigest()
    return json.dumps(
        {**data, "mac": mac}, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("ascii")
