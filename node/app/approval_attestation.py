"""Read-only offline Node attestation signing primitive for independent review.

NOT an HTTP endpoint. No mutation of FRPS, FRPC, lease DB, inbound or pairing.
The Node's private Ed25519 approval-attestation key is a dedicated, root-only
secret; neither Smite Panel nor its normal Signed Agent key may access it.
The caller must derive facts from verified LOCAL runtime state, never from
Panel-provided JSON. Production sources/keys are not provisioned by this file.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import stat
import time

AUDIENCE = "u-opti:stage15:root-review-evidence:v1"
IDENT = re.compile(r"[A-Za-z0-9_-]{8,128}\Z")
KINDS = {"frps_owner", "active_lease", "xhttp_inbound"}
PATH = re.compile(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\Z")


class AttestationHold(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _private_key(key_path: Path):
    try:
        info = key_path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400
                or info.st_size != 32):
            raise AttestationHold("INDEPENDENT_NODE_KEY_NOT_PROVISIONED")
        fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino):
                raise AttestationHold("INDEPENDENT_NODE_KEY_CHANGED")
            raw = os.read(fd, 33)
        finally:
            os.close(fd)
        if len(raw) != 32:
            raise AttestationHold("INDEPENDENT_NODE_KEY_INVALID")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (OSError, ValueError, ImportError) as exc:
        raise AttestationHold("INDEPENDENT_NODE_KEY_UNAVAILABLE") from exc


def _checked_facts(kind: str, facts: dict) -> None:
    if kind == "frps_owner":
        if (set(facts) != {"tunnel_id", "control_port", "proxy_port"}
                or type(facts["tunnel_id"]) is not str
                or not IDENT.fullmatch(facts["tunnel_id"])
                or type(facts["control_port"]) is not int or facts["control_port"] != 7000
                or type(facts["proxy_port"]) is not int
                or not 1024 <= facts["proxy_port"] <= 65535
                or facts["proxy_port"] == 7000):
            raise AttestationHold("INVALID_OWNER_FACTS")
    elif kind == "xhttp_inbound":
        if (set(facts) != {"port", "listen", "protocol", "network", "path", "enabled"}
                or type(facts["port"]) is not int
                or not 1024 <= facts["port"] <= 65535
                or facts["listen"] != "127.0.0.1" or facts["protocol"] != "vless"
                or facts["network"] != "xhttp" or facts["enabled"] is not True
                or type(facts["path"]) is not str or len(facts["path"]) > 128
                or not PATH.fullmatch(facts["path"])):
            raise AttestationHold("INVALID_INBOUND_FACTS")
    elif kind == "active_lease":
        required = {"ir_node", "kh_node", "owner", "child", "lease",
                    "port", "role", "state", "unique", "owner_count", "proxy_port_count"}
        if (set(facts) != required
                or any(type(facts[k]) is not str or not IDENT.fullmatch(facts[k])
                       for k in ("ir_node", "kh_node", "owner", "child", "lease"))
                or type(facts["port"]) is not int or not 1024 <= facts["port"] <= 65535
                or facts["role"] not in ("direct", "shared")
                or (facts["role"] == "direct") != (facts["owner"] == facts["child"])
                or (facts["role"] == "direct" and facts["lease"] != facts["child"])
                or (facts["role"] == "shared" and facts["lease"] != facts["child"])
                or facts["state"] != "active" or facts["unique"] is not True
                or type(facts["owner_count"]) is not int or facts["owner_count"] != 1
                or type(facts["proxy_port_count"]) is not int or facts["proxy_port_count"] != 1):
            raise AttestationHold("INVALID_LIVE_LEASE_FACTS")
    else:
        raise AttestationHold("UNSUPPORTED_ATTESTATION_KIND")


def attest(*, kind: str, node_id: str, facts: dict, nonce: str,
           key_path: Path, now: int | None = None) -> dict:
    """Sign strict LOCAL snapshots only; no caller/network state changes.

    NOTE: a future root-owned runtime collector MUST establish live facts
    independently of Panel-supplied values. This primitive is not that collector.
    """
    now = int(time.time()) if now is None else now
    if (type(node_id) is not str or not IDENT.fullmatch(node_id)
            or type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or type(now) is not int or not 0 <= now < 2**63 - 30
            or type(facts) is not dict or kind not in KINDS):
        raise AttestationHold("INVALID_ATTESTATION_CONTEXT")
    _checked_facts(kind, facts)
    wire = {"schema": 1, "audience": AUDIENCE, "kind": kind,
            "node": node_id, "issued_at": now, "expires_at": now + 30,
            "nonce": nonce, "facts": facts}
    signature = _private_key(key_path).sign(canonical(wire))
    wire["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return wire
