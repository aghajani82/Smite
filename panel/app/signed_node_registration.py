"""Signed Node->Panel enrollment and FRP heartbeats; DEFAULT OFF.

Uses the same independently encrypted per-Node key as pairing. Replay
rejection is persisted in the existing Panel SQLite database (atomic unique
nonce insertion). No replay table is auto-created on service startup.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import re
import sqlite3

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app import node_auth, node_pairing_store
from app.config import settings


_ID = re.compile(r"^[a-zA-Z0-9_-]{8,80}$")
_MAX_BODY = 8192


class SignedRegistrationUnavailable(RuntimeError):
    pass


def initialize_replay_schema(database_path: str | Path) -> None:
    """Operator-driven migration AFTER Panel DB backup. Not called on import."""
    path = Path(database_path)
    if not path.is_file():
        raise SignedRegistrationUnavailable("Database must exist")
    with closing(sqlite3.connect(path, timeout=10, isolation_level=None)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Pairing store migration must already exist.
            if conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                "AND name='smite_node_identities'"
            ).fetchone()[0] != 1:
                raise SignedRegistrationUnavailable("Pairing migration missing")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS smite_node_inbound_nonces "
                "(node_id TEXT NOT NULL, nonce TEXT NOT NULL, "
                "expires_at INTEGER NOT NULL, PRIMARY KEY (node_id, nonce))"
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


class ReplayStore:
    skew_seconds = node_auth.MAX_CLOCK_SKEW

    def __init__(self, path: str | Path, *, capacity: int = 100_000):
        if capacity < 1:
            raise ValueError("Invalid replay capacity")
        self.path = Path(path)
        self.capacity = capacity

    def register(self, node_id: str, nonce: str, now: int) -> bool:
        if not self.path.is_file():
            raise SignedRegistrationUnavailable("Replay storage unavailable")
        with closing(sqlite3.connect(self.path, timeout=10, isolation_level=None)) as conn:
            conn.execute("PRAGMA busy_timeout=10000")
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM smite_node_inbound_nonces WHERE expires_at < ?", (now,))
                count = conn.execute(
                    "SELECT COUNT(*) FROM smite_node_inbound_nonces"
                ).fetchone()[0]
                if count >= self.capacity:
                    conn.rollback()
                    return False
                conn.execute(
                    "INSERT INTO smite_node_inbound_nonces(node_id,nonce,expires_at)"
                    " VALUES(?,?,?)",
                    (node_id, nonce, now + self.skew_seconds * 2),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
            except sqlite3.Error as exc:
                conn.rollback()
                raise SignedRegistrationUnavailable("Replay verification failed") from exc


def _verify(*, method: str, target: str, headers: dict[str, str],
            body: bytes, now: int | None = None) -> str:
    if settings.db_type != "sqlite" or not settings.smite_node_pairing_master_key:
        raise SignedRegistrationUnavailable("Signed registration configuration missing")
    node_id = headers.get("x-smite-node-id", "")
    if not _ID.fullmatch(node_id) or not Path(settings.db_path).is_file():
        # Do not disclose whether a Node ID exists.
        raise node_auth.NodeAuthError("Unauthorized signed request")
    try:
        secret = node_pairing_store.get_active_secret(
            settings.db_path, master_key=settings.smite_node_pairing_master_key,
            node_id=node_id,
        )
    except node_pairing_store.PairingDenied as exc:
        raise node_auth.NodeAuthError("Unauthorized signed request") from exc
    if not node_auth.verify_request(
        secret=secret, node_id=node_id, method=method, target=target, body=body,
        headers=headers, replay=ReplayStore(settings.db_path), now=now,
    ):
        raise node_auth.NodeAuthError("Unauthorized signed request")
    return node_id


async def authenticated_node(request: Request) -> tuple[str, bytes]:
    """Verify exact incoming signed wire bytes before any DB write."""
    if settings.smite_node_registration_mode != "signed":
        raise HTTPException(status_code=503, detail="Signed registration disabled")
    size = request.headers.get("content-length")
    if size is not None:
        try:
            if not 0 <= int(size) <= _MAX_BODY:
                raise HTTPException(413, detail="Request body too large")
        except ValueError as exc:
            raise HTTPException(400, detail="Invalid content length") from exc
    body = await request.body()
    if len(body) > _MAX_BODY:
        raise HTTPException(413, detail="Request body too large")

    raw = request.scope.get("raw_path", b"")
    query = request.scope.get("query_string", b"")
    if not isinstance(raw, bytes) or not isinstance(query, bytes):
        raise HTTPException(400, detail="Malformed request")
    if b"?" in raw:
        raw_path, embedded = raw.split(b"?", 1)
        if embedded != query:
            raise HTTPException(400, detail="Malformed request")
        raw = raw_path
    try:
        target = (raw + (b"?" + query if query else b"")).decode("ascii")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, detail="Malformed request") from exc
    if target not in ("/api/node-control/register", "/api/node-control/frp-status"):
        raise HTTPException(404, detail="Not found")
    try:
        node_id = await run_in_threadpool(
            _verify, method=request.method, target=target,
            headers={k.lower(): v for k, v in request.headers.items()},
            body=body,
        )
    except node_auth.NodeAuthError as exc:
        raise HTTPException(401, detail="Unauthorized signed Node") from exc
    except (SignedRegistrationUnavailable, sqlite3.Error, ValueError) as exc:
        raise HTTPException(503, detail="Node authentication unavailable") from exc
    return node_id, body
