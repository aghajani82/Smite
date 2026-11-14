"""Privately administrator-approved Node control origins, read-only Stage12.

In signed mode NEVER route an authenticated Agent command via the legacy
Node.metadata.api_address/control_address. Those fields historically came
from anonymous registration and are NOT an origin trust source.

Approval file is manually provisioned out-of-band and is NOT created here.
No API route can write it. Default signed mode remains OFF. Only a trusted
HTTPS/443 origin for a foreign Node, or verified localhost:8888 for an
Iran Node co-located with the Panel, is accepted. FRP relay addresses must
be pinned separately in a later migration; no dynamic fallback to
legacy metadata/frp_remote_port is permitted.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sqlite3
from contextlib import closing
from urllib.parse import urlsplit

from app.config import settings


_ID = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
_FQDN = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class ApprovedOriginUnavailable(RuntimeError):
    pass


def _origin(origin: str, role: str) -> str:
    if not isinstance(origin, str) or any(ch.isspace() for ch in origin):
        raise ApprovedOriginUnavailable("Invalid approved Node origin")
    try:
        url = urlsplit(origin)
        host, port = url.hostname, url.port
    except (ValueError, TypeError) as exc:
        raise ApprovedOriginUnavailable("Invalid approved Node origin") from exc
    if (
        not host or url.username is not None or url.password is not None
        or url.path or url.query or url.fragment
    ):
        raise ApprovedOriginUnavailable("Origin must be a bare URL")
    if url.scheme == "http":
        if role != "iran" or host != "127.0.0.1" or port != 8888:
            raise ApprovedOriginUnavailable("Cleartext origin not approved")
        return "http://127.0.0.1:8888"
    if url.scheme != "https" or port not in (None, 443):
        raise ApprovedOriginUnavailable("Signed origin requires HTTPS/443")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ApprovedOriginUnavailable("TLS origin must be a DNS name")
    if not _FQDN.fullmatch(host.lower()):
        raise ApprovedOriginUnavailable("Signed origin hostname invalid")
    return f"https://{host.lower()}:443"


def _control_address(control: str, approved_origin: str, role: str) -> str:
    if not isinstance(control, str) or not control:
        raise ApprovedOriginUnavailable("Missing approved Node control URL")
    try:
        parts = urlsplit(control)
    except ValueError as exc:
        raise ApprovedOriginUnavailable("Invalid control URL") from exc
    if (
        parts.query or parts.fragment or parts.username or parts.password
        or not parts.path.startswith("/") or parts.path == "/"
    ):
        raise ApprovedOriginUnavailable("Invalid control URL path")
    base = _origin(f"{parts.scheme}://{parts.netloc}", role)
    if base != approved_origin:
        raise ApprovedOriginUnavailable("Control hostname not approved")
    # Normalized path is for matching legacy U-OPTI gateway evidence ONLY;
    # outgoing signed Agent traffic uses /api/agent/* on that origin.
    if any(ch.isspace() for ch in parts.path) or "//" in parts.path or ".." in parts.path or "%" in parts.path or "\\" in parts.path:
        raise ApprovedOriginUnavailable("Control path invalid")
    return base + parts.path.rstrip("/")


def _file_node(node_id: str, *, optional: bool = False) -> dict[str, str] | None:
    if not isinstance(node_id, str) or not _ID.fullmatch(node_id):
        raise ApprovedOriginUnavailable("Node identity invalid")
    path = Path(settings.smite_signed_node_origins_path)
    parent = path.parent
    try:
        par = parent.lstat()
        if (
            not stat.S_ISDIR(par.st_mode) or par.st_uid != os.geteuid()
            or stat.S_IMODE(par.st_mode) != 0o700
        ):
            raise ApprovedOriginUnavailable("Trusted Node store directory unsafe")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            file = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(file.st_mode)
                or file.st_uid != os.geteuid()
                or stat.S_IMODE(file.st_mode) != 0o600
                or file.st_size > 64_000
            ):
                raise ApprovedOriginUnavailable("Trusted Node file unsafe")
            data = json.loads(stream.read(64_001))
    except FileNotFoundError as exc:
        if optional:
            return None
        raise ApprovedOriginUnavailable("Trusted Node store unavailable") from exc
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise ApprovedOriginUnavailable("Trusted Node store unavailable") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ApprovedOriginUnavailable("Unsupported trusted Node schema")
    nodes = data.get("nodes")
    if not isinstance(nodes, dict):
        raise ApprovedOriginUnavailable("Trusted Node list missing")
    if optional and node_id not in nodes:
        return None
    found = nodes.get(node_id)
    if not isinstance(found, dict):
        raise ApprovedOriginUnavailable("Node not administrator-approved")
    role, name = found.get("role"), found.get("node_name")
    if role not in ("iran", "foreign") or not isinstance(name, str) or not (1 <= len(name) <= 128):
        raise ApprovedOriginUnavailable("Approved Node role/name invalid")
    origin = _origin(found.get("origin"), role)
    control_url = _control_address(found.get("control_url"), origin, role)
    return {"node_id": node_id, "role": role, "node_name": name,
            "origin": origin, "control_url": control_url}


def control_url_matches(pin: dict[str, str], claimed: str) -> bool:
    """Compare a paired Node's claimed URL after strict, safe canonicalization."""
    try:
        return _control_address(claimed, pin["origin"], pin["role"]) == pin["control_url"]
    except (ApprovedOriginUnavailable, KeyError, TypeError):
        return False


def _database_node(node_id: str) -> dict[str, str] | None:
    """Read one coherent snapshot; never create/migrate or trust metadata URLs."""
    from app import foreign_install_grants as grants
    path = Path(settings.db_path)
    if settings.db_type != "sqlite" or path.is_symlink() or not path.is_file():
        raise ApprovedOriginUnavailable("Installation origin database unavailable")
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            db.execute("BEGIN")
            origin = db.execute("SELECT * FROM smite_foreign_install_origins WHERE node_id=?", (node_id,)).fetchone()
            if origin is None:
                if db.execute("SELECT 1 FROM smite_foreign_install_grants WHERE node_id=? AND consumed_at IS NOT NULL", (node_id,)).fetchone():
                    raise ApprovedOriginUnavailable("Committed installation origin missing")
                return None
            grant = db.execute("SELECT * FROM smite_foreign_install_grants WHERE code_hash=?", (origin["grant_hash"],)).fetchone()
            identity = db.execute("SELECT * FROM smite_node_identities WHERE node_id=?", (node_id,)).fetchone()
            if (not grant or not identity or identity["revoked_at"] is not None
                    or identity["node_role"] != "foreign" or grant["revoked_at"] is not None
                    or grant["consumed_at"] is None
                    or not grant["issued_at"] <= grant["consumed_at"] < grant["expires_at"]
                    or identity["paired_at"] != grant["consumed_at"]
                    or origin["approved_at"] != grant["consumed_at"]
                    or any(origin[key] != grant[key] for key in ("node_id", "node_name", "origin", "control_url"))
                    or not grants._node(db, node_id, origin["node_name"], paired=True)):
                raise ApprovedOriginUnavailable("Installation origin evidence invalid")
            base = _origin(origin["origin"], "foreign")
            host = urlsplit(base).hostname
            grants.normalize_domain(host)
            control = _control_address(origin["control_url"], base, "foreign")
            if (base != origin["origin"] or control != origin["control_url"]
                    or not grants._PATH.fullmatch(control[len(base):])):
                raise ApprovedOriginUnavailable("Installation origin binding invalid")
            return {"node_id": node_id, "role": "foreign", "node_name": origin["node_name"],
                    "origin": base, "control_url": control}
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, IndexError) as exc:
        raise ApprovedOriginUnavailable("Installation origin unavailable") from exc


def approved_node(node_id: str) -> dict[str, str]:
    if not isinstance(node_id, str) or not _ID.fullmatch(node_id):
        raise ApprovedOriginUnavailable("Node identity invalid")
    # Trust is separate from issuance: stopping new grants must not disconnect
    # enrolled Nodes. Enabling trust requires an explicit schema migration.
    if not settings.smite_foreign_install_origin_trust_enabled:
        return _file_node(node_id)
    file_pin = _file_node(node_id, optional=True)
    database_pin = _database_node(node_id)
    if database_pin is not None:
        if file_pin is not None and file_pin != database_pin:
            raise ApprovedOriginUnavailable("Conflicting approved Node origins")
        return {**database_pin, "origin_source": "installation_grant"}
    if file_pin is not None:
        return file_pin
    raise ApprovedOriginUnavailable("Node not administrator-approved")
