"""Approved, read-only Sanaei/3x-ui VLESS XHTTP inbound inventory.

This does NOT manage Sanaei, query its HTTP admin API, read client UUIDs,
or apply FRP. The operator must explicitly configure an approved read-only
bind mount for x-ui.db on the foreign Node. Unavailable/malformed data HOLDs
closed. Never accept a database path from a remote HTTP request.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import stat


class SanaeiInventoryUnavailable(RuntimeError):
    """Fail-closed, non-secret status for an unavailable inbound inventory."""


_PATH = re.compile(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\Z")
_REQUIRED = {"port", "listen", "protocol", "stream_settings", "enable"}
MAX_INBOUNDS = 128
MAX_DB_BYTES = 128 * 1024 * 1024


def _checked_db(path: str) -> Path:
    # Configured on the trusted Node only; no caller-supplied path or raw URL.
    if not isinstance(path, str) or not path.startswith("/"):
        raise SanaeiInventoryUnavailable("Approved Sanaei inventory path unavailable")
    p = Path(path)
    if ".." in p.parts:
        raise SanaeiInventoryUnavailable("Unapproved Sanaei inventory path")
    try:
        info = p.lstat()
    except OSError as exc:
        raise SanaeiInventoryUnavailable("Sanaei inventory file unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or bool(info.st_mode & 0o022)
            or not 0 < info.st_size <= MAX_DB_BYTES):
        raise SanaeiInventoryUnavailable("Sanaei inventory file untrusted")
    # WAL readers need the sidecars in the SAME directory mount. Reject links,
    # unexpected owners and writable-to-others artifacts, never repair them.
    companions = []
    for suffix, maximum in (("-wal", MAX_DB_BYTES), ("-shm", 4 * 1024 * 1024)):
        side = p.with_name(p.name + suffix)
        try:
            meta = side.lstat()
        except FileNotFoundError:
            companions.append(False)
            continue
        except OSError as exc:
            raise SanaeiInventoryUnavailable("Sanaei WAL sidecar unavailable") from exc
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
                or meta.st_uid != info.st_uid or meta.st_mode & 0o022
                or not 0 <= meta.st_size <= maximum):
            raise SanaeiInventoryUnavailable("Untrusted Sanaei WAL sidecar")
        companions.append(True)
    if companions[0] != companions[1]:
        raise SanaeiInventoryUnavailable("Incomplete Sanaei WAL view")
    return p


def list_approved_xhttp_inbounds(db_path: str) -> list[dict[str, object]]:
    """Return *only* non-secret inbound facts; no credentials or raw JSON.

    The database must be a separately authorized and protected local mount.
    Connection uses immutable-disabled SQLite read-only mode so WAL-backed
    changes can be visible without writing to the source database.
    """
    db = _checked_db(db_path)
    try:
        with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=1) as conn:
            conn.execute("PRAGMA query_only = ON")
            schema = {r[1] for r in conn.execute("PRAGMA table_info(inbounds)")}
            if not _REQUIRED.issubset(schema):
                raise SanaeiInventoryUnavailable("Unsupported Sanaei inbound schema")
            rows = conn.execute(
                "SELECT port, listen, protocol, stream_settings, enable FROM inbounds"
            ).fetchmany(MAX_INBOUNDS + 1)
            if len(rows) > MAX_INBOUNDS:
                raise SanaeiInventoryUnavailable("Sanaei inbound inventory too large")
    except (OSError, sqlite3.Error) as exc:
        raise SanaeiInventoryUnavailable("Sanaei inbound read unavailable") from exc

    found: list[dict[str, object]] = []
    used_ports: set[int] = set()
    used_paths: set[str] = set()
    for port, listen, protocol, stream_settings, enable in rows:
        if protocol != "vless" or enable not in (1, True):
            continue
        try:
            stream = json.loads(stream_settings)
        except (TypeError, ValueError) as exc:
            raise SanaeiInventoryUnavailable("Malformed enabled inbound transport") from exc
        if not isinstance(stream, dict):
            raise SanaeiInventoryUnavailable("Malformed enabled inbound transport")
        if stream.get("network") != "xhttp":
            continue

        if (type(port) is not int or not 1024 <= port <= 65535
                or listen != "127.0.0.1"):
            raise SanaeiInventoryUnavailable("XHTTP inbound must be loopback and valid")
        settings = stream.get("xhttpSettings")
        exact_path = settings.get("path") if isinstance(settings, dict) else None
        if (not isinstance(exact_path, str) or len(exact_path) > 128
                or not _PATH.fullmatch(exact_path)
            or exact_path.split("/")[1].lower() in {"api", "docs", "redoc", "openapi", "assets", "static", "auth", "login", "admin", "health", "metrics", "sub", "ws"}
                or any(exact_path == p or exact_path.startswith(p + "/") or p.startswith(exact_path + "/") for p in used_paths) or port in used_ports):
            raise SanaeiInventoryUnavailable("Unapproved or conflicting XHTTP path")
        used_ports.add(port)
        used_paths.add(exact_path)
        found.append({
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "network": "xhttp",
            "path": exact_path,
            "enabled": True,
        })
    return sorted(found, key=lambda x: int(x["port"]))
