"""Smite Node ↔ Panel HMAC request envelope (v1).

Cryptographic primitive only. Application routes do not enforce this until
Node enrollment, secret provisioning, authenticated clients and staged
migration are in place. NEVER treat this module's presence as enforcement.

Secrets are per-node random bytes, distinct from user JWTs and FRP tokens.
No secrets or signatures should be sent in query strings or logged.
"""
from __future__ import annotations

from collections import OrderedDict
from hashlib import sha256
import hmac
import re
import secrets
import threading
import time


VERSION = "smite-node-hmac-v1"
MAX_CLOCK_SKEW = 90  # seconds; hosts must have synchronized clocks
_NONCE = re.compile(r"^[a-f0-9]{32}$")
_SIGNATURE = re.compile(r"^[a-f0-9]{64}$")
_NODE_ID = re.compile(r"^[a-zA-Z0-9_-]{8,80}$")
_METHOD = re.compile(r"^[A-Z]{3,10}$")


class NodeAuthError(ValueError):
    """Authentication failed; callers should return generic 401."""


def _secret_bytes(secret: bytes | str) -> bytes:
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise NodeAuthError("Node identity key is not provisioned")
    return secret


def _canonical(
    *, node_id: str, method: str, target: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
        raise NodeAuthError("Invalid node identity")
    if not isinstance(method, str) or not _METHOD.fullmatch(method):
        raise NodeAuthError("Invalid HTTP method")
    if not isinstance(target, str) or not target.startswith("/") or any(c in target for c in ("\n", "\r", "#")):
        raise NodeAuthError("Invalid HTTP target")
    if not isinstance(timestamp, str) or not timestamp.isascii() or not timestamp.isdecimal() or len(timestamp) > 11:
        raise NodeAuthError("Invalid timestamp")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise NodeAuthError("Invalid nonce")
    if not isinstance(body, bytes):
        raise NodeAuthError("Request body must be raw bytes")

    body_digest = sha256(body).hexdigest()
    fields = (VERSION, node_id, method, target, timestamp, nonce, body_digest)
    return "\n".join(fields).encode("utf-8")


def sign_request(
    *, secret: bytes | str, node_id: str, method: str, target: str,
    body: bytes = b"", timestamp: int | None = None, nonce: str | None = None
) -> dict[str, str]:
    """Return headers for one raw HTTP request (never reuse a nonce)."""
    key = _secret_bytes(secret)
    moment = str(int(time.time()) if timestamp is None else timestamp)
    rand = secrets.token_hex(16) if nonce is None else nonce
    message = _canonical(
        node_id=node_id, method=method.upper(), target=target,
        timestamp=moment, nonce=rand, body=body,
    )
    signature = hmac.new(key, message, "sha256").hexdigest()
    return {
        "X-Smite-Node-ID": node_id,
        "X-Smite-Timestamp": moment,
        "X-Smite-Nonce": rand,
        "X-Smite-Signature": signature,
    }


class NonceWindow:
    """Per-worker bounded replay cache.

    Production with multiple panel workers or multiple processes MUST use a
    shared persistent/atomic replay store; do not enable strict auth with
    this cache alone across a cluster.
    """

    def __init__(self, *, skew_seconds: int = MAX_CLOCK_SKEW, max_entries: int = 100_000):
        if skew_seconds < 1 or max_entries < 1:
            raise ValueError("Invalid replay window")
        self.skew_seconds = skew_seconds
        self.max_entries = max_entries
        self._seen: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._lock = threading.Lock()

    def register(self, node_id: str, nonce: str, now: int) -> bool:
        key = (node_id, nonce)
        with self._lock:
            expiration_cutoff = now - 2 * self.skew_seconds
            while self._seen:
                oldest_key = next(iter(self._seen))
                if self._seen[oldest_key] > expiration_cutoff:
                    break
                self._seen.popitem(last=False)
            if key in self._seen or len(self._seen) >= self.max_entries:
                return False
            self._seen[key] = now
            return True


def verify_request(
    *, secret: bytes | str, node_id: str, method: str, target: str,
    body: bytes, headers: dict[str, str], replay: NonceWindow, now: int | None = None
) -> bool:
    """Authenticate signed request and atomically reject duplicate nonce.

    Only pass a secret from an authenticated node-identity lookup. The
    request header's node ID is merely a selector, not proof of identity.
    """
    key = _secret_bytes(secret)
    values = {k.lower(): v for k, v in headers.items()}
    signed_node_id = values.get("x-smite-node-id", "")
    timestamp = values.get("x-smite-timestamp", "")
    nonce = values.get("x-smite-nonce", "")
    signature = values.get("x-smite-signature", "")
    if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
        return False
    if signed_node_id != node_id:
        return False
    try:
        signed_at = int(timestamp)
        current = int(time.time()) if now is None else now
        if abs(current - signed_at) > replay.skew_seconds:
            return False
        canonical = _canonical(
            node_id=node_id, method=method.upper(), target=target,
            timestamp=timestamp, nonce=nonce, body=body,
        )
    except (NodeAuthError, ValueError, TypeError):
        return False

    expected = hmac.new(key, canonical, "sha256").hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False
    return replay.register(node_id, nonce, current)
