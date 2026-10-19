"""Read-only, explicit tunnel-engine inventory (review-only, fail closed).

Bundled binaries are NOT installed engines. A trusted root-only manifest
must explicitly enroll an engine AND pin the exact SHA256 of its in-Node
binary. A malformed manifest cannot quietly become an empty/ready set.
No endpoint may edit the registry or start an engine.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from app.config import settings


ENGINES = ("backhaul", "frp", "gost", "rathole", "chisel")
# Production binaries are always expected to be owned by root (uid 0).
# Unit tests patch only this reference to their disposable fixture owner.
ROOT_BINARY_UID = 0
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class EngineInventoryUnavailable(RuntimeError):
    pass


def binary_path_for_engine(name: str) -> Path:
    """Fixed in-container targets; user-supplied paths are NEVER trusted."""
    if name not in ENGINES:
        raise EngineInventoryUnavailable("Unknown engine")
    return Path("/usr/local/bin") / ("frpc" if name == "frp" else name)


def _trusted_manifest(path: Path) -> dict | None:
    parent = path.parent
    if path.is_symlink() or parent.is_symlink():
        raise EngineInventoryUnavailable("Unsafe engine inventory path")
    if not path.exists():
        if parent.exists():
            _validate_dir(parent)
        return None
    _validate_dir(parent)
    st = path.lstat()
    if (
        not stat.S_ISREG(st.st_mode)
        or st.st_uid != os.geteuid()
        or stat.S_IMODE(st.st_mode) & 0o177 != 0
        or st.st_nlink != 1
        or st.st_size > 8192
    ):
        raise EngineInventoryUnavailable("Unsafe engine inventory file")
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise EngineInventoryUnavailable("Invalid engine inventory") from exc
    if not isinstance(body, dict) or set(body) != {"schema", "engines"} or body["schema"] != 1:
        raise EngineInventoryUnavailable("Unknown engine inventory schema")
    declared = body["engines"]
    if not isinstance(declared, dict) or not set(declared).issubset(ENGINES):
        raise EngineInventoryUnavailable("Invalid engine inventory declarations")
    for name, item in declared.items():
        if not isinstance(item, dict) or not isinstance(item.get("sha256"), str) or not _SHA256.fullmatch(item["sha256"]):
            raise EngineInventoryUnavailable("Invalid engine artifact digest")
        # Managed FRP requires *both* roles: a pinned frpc AND frps.
        # Old frpc-only declarations remain parseable for safe inventory
        # migration, but can never produce "ready" until frps is pinned.
        fields = set(item)
        if name == "frp":
            if fields not in ({"sha256"}, {"sha256", "server_sha256"}):
                raise EngineInventoryUnavailable("Unknown FRP engine manifest fields")
            if "server_sha256" in item and (
                not isinstance(item["server_sha256"], str)
                or not _SHA256.fullmatch(item["server_sha256"])
            ):
                raise EngineInventoryUnavailable("Invalid FRP server digest")
        elif fields != {"sha256"}:
            raise EngineInventoryUnavailable("Unknown engine manifest fields")
    return declared


def _validate_dir(parent: Path) -> None:
    try:
        st = parent.lstat()
    except OSError as exc:
        raise EngineInventoryUnavailable("Engine inventory directory missing") from exc
    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != os.geteuid()
        or stat.S_IMODE(st.st_mode) & 0o077
    ):
        raise EngineInventoryUnavailable("Unsafe engine inventory directory")


def engine_inventory() -> dict:
    """Return only non-secret engine states, never local paths or hashes."""
    if settings.smite_engine_inventory_mode != "managed":
        return {"mode": "legacy", "engines": {
            name: "unmanaged" for name in ENGINES
        }}
    path = Path(settings.smite_engine_manifest_path)
    declared = _trusted_manifest(path)
    result = {}
    for name in ENGINES:
        if declared is None or name not in declared:
            result[name] = "not-installed"
            continue
        binary = binary_path_for_engine(name)
        try:
            st = binary.lstat()
            if (
                binary.is_symlink()
                or not stat.S_ISREG(st.st_mode)
                or st.st_uid != ROOT_BINARY_UID
                or not st.st_mode & 0o111
                or st.st_mode & 0o022
            ):
                result[name] = "unavailable"
                continue
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            if digest != declared[name]["sha256"]:
                result[name] = "unavailable"
                continue
            if name == "frp":
                server_digest = declared[name].get("server_sha256")
                server = Path("/usr/local/bin/frps")
                # An older frpc-only manifest must never claim FRP ready.
                if server_digest is None or server.is_symlink():
                    result[name] = "unavailable"
                    continue
                st_server = server.lstat()
                if (not stat.S_ISREG(st_server.st_mode)
                    or st_server.st_uid != ROOT_BINARY_UID
                    or not st_server.st_mode & 0o111
                    or st_server.st_mode & 0o022
                    or hashlib.sha256(server.read_bytes()).hexdigest() != server_digest):
                    result[name] = "unavailable"
                    continue
            result[name] = "ready"
        except OSError:
            result[name] = "unavailable"
    return {"mode": "managed", "engines": result}


def require_engine_ready(core: str) -> None:
    if settings.smite_engine_inventory_mode == "legacy":
        return
    current = engine_inventory()
    if current["engines"].get(core) != "ready":
        raise EngineInventoryUnavailable("Selected tunnel engine is not ready")
