"""Opt-in, certificate-verified Node pairing client, not wired into startup.

Designed for future U-OPTI wizard: enter code via a private input prompt and
send in HTTPS POST body only. Never use the existing PanelClient(verify=False).
No redirects, proxy auto-discovery, query strings or credentials in the URL.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

import httpx


_UUID = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
_SECRET = re.compile(r"^[a-f0-9]{64}$")


class PairingClientError(RuntimeError):
    pass


def _endpoint(panel_url: str) -> str:
    if not isinstance(panel_url, str):
        raise PairingClientError("HTTPS panel URL required")
    parts = urlsplit(panel_url)
    if (
        parts.scheme != "https" or not parts.hostname
        or parts.username or parts.password or parts.query or parts.fragment
        or parts.path not in ("", "/")
        or parts.port not in (None, 443)
    ):
        raise PairingClientError("Pairing requires a plain HTTPS/443 panel origin")
    return panel_url.rstrip("/") + "/api/node-pairing/redeem"


def _validate_private_destination(dest: Path) -> None:
    """Verify local safe storage BEFORE consuming the one-time code."""
    if dest.exists() or dest.is_symlink():
        raise PairingClientError("Identity exists: never overwrite or auto-rotate")
    try:
        info = dest.parent.lstat()
    except OSError as exc:
        raise PairingClientError("Identity directory missing") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise PairingClientError("Identity directory must be owned and mode 0700")


def store_identity(destination: str | Path, *, node_id: str, secret: str) -> None:
    """Create an unreadable-to-others identity, refusing existing destinations.

    The parent is expected to be a provisioned, owned, private directory.
    This implementation does not follow symlinks or replace credentials.
    """
    if (
        not isinstance(node_id, str) or not _UUID.fullmatch(node_id)
        or not isinstance(secret, str) or not _SECRET.fullmatch(secret)
    ):
        raise PairingClientError("Invalid Node identity response")
    dest = Path(destination)
    _validate_private_destination(dest)
    data = json.dumps(
        {"version": 1, "node_id": node_id, "node_secret": secret},
        separators=(",", ":"), sort_keys=True,
    ).encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(dest, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        dest.unlink(missing_ok=True)
        raise


def redeem_and_store(
    *, panel_url: str, pairing_code: str, node_id: str, role: str,
    destination: str | Path, timeout_seconds: int = 15,
) -> str:
    """Exchange a code over verified HTTPS; only return the non-secret Node ID."""
    url = _endpoint(panel_url)
    if not _UUID.fullmatch(node_id) or role not in ("iran", "foreign"):
        raise PairingClientError("Invalid Node identity scope")
    if not isinstance(pairing_code, str) or len(pairing_code) > 128 or not pairing_code.startswith("smn1_"):
        raise PairingClientError("Invalid Node pairing code")
    dest = Path(destination)
    _validate_private_destination(dest)

    # No verify=False: system CA chain and DNS hostname verification required.
    # No environment proxy to silently intercept pairing credentials.
    # No redirects: do not leak code to a different origin.
    try:
        with httpx.Client(
            timeout=timeout_seconds, verify=True, trust_env=False,
            follow_redirects=False,
        ) as client:
            result = client.post(
                url,
                json={"pairing_code": pairing_code, "node_id": node_id, "role": role},
                headers={"Cache-Control": "no-store", "Accept": "application/json"},
            )
            if result.status_code != 200:
                raise PairingClientError("Pairing failed; check HTTPS gateway and approval")
            payload = result.json()
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        raise PairingClientError("Secure pairing request failed") from exc
    if not isinstance(payload, dict) or payload.get("node_id") != node_id:
        raise PairingClientError("Pairing identity mismatch")
    store_identity(dest, node_id=node_id, secret=payload.get("node_secret", ""))
    return node_id
