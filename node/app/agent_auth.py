"""Opt-in Agent request auth with durable SQLite replay rejection.

Default mode: legacy (no change to running nodes). Strict requires a private
paired identity and a persistent anti-replay database. No silent fallback.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.config import settings
from app import node_auth


_NODE_ID = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
_SECRET = re.compile(r"^[a-f0-9]{64}$")
_NONCE = re.compile(r"^[a-f0-9]{32}$")
MAX_REQUEST_BODY = 1_048_576


class AgentAuthUnavailable(RuntimeError):
    """Fail-closed configuration/store failure."""


def _private_parent(path: Path) -> None:
    try:
        info = path.parent.lstat()
    except OSError as exc:
        raise AgentAuthUnavailable("Private Agent directory missing") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise AgentAuthUnavailable("Private Agent directory must be owned and mode 0700")


def read_identity(file: str | Path) -> tuple[str, bytes]:
    """Load Node identity from root-owned 0600 JSON, never follow symlinks."""
    path = Path(file)
    _private_parent(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 4096
            ):
                raise AgentAuthUnavailable("Node identity has unsafe permissions")
            data = json.loads(stream.read(4097))
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise AgentAuthUnavailable("Cannot load valid Node identity") from exc
    node_id = data.get("node_id") if isinstance(data, dict) else None
    secret = data.get("node_secret") if isinstance(data, dict) else None
    if (
        not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id)
        or not isinstance(secret, str) or not _SECRET.fullmatch(secret)
    ):
        raise AgentAuthUnavailable("Node identity is invalid")
    return node_id, secret.encode("ascii")


REPLAY_SCHEMA_VERSION = 1


class DurableNonceStore:
    """Persistent, pre-provisioned replay store; NEVER re-create at request time.

    Strict Agent requests must fail closed when the replay DB disappears,
    loses its schema or belongs to another paired Node identity. Bootstrap
    is a separate explicit provisioning operation, never a request fallback.
    """

    skew_seconds = node_auth.MAX_CLOCK_SKEW

    def __init__(self, database: str | Path, max_entries: int = 100_000):
        self.database = Path(database)
        if max_entries < 1:
            raise ValueError("Invalid replay capacity")
        self.max_entries = max_entries

    @staticmethod
    def initialize_new(database: str | Path, node_id: str) -> None:
        """ONE-TIME explicit offline enrollment only; never called by API.

        Refuses existing files, even if damaged or empty, to avoid clearing
        historical nonces. Caller must pair the Node first and retain the
        store through container recreation. Failed bootstrap needs review,
        not an automatic delete/retry.
        """
        if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
            raise AgentAuthUnavailable("Invalid replay store Node identity")
        path = Path(database)
        _private_parent(path)
        fd = None
        try:
            fd = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                getattr(os, "O_NOFOLLOW", 0), 0o600,
            )
            os.fsync(fd)
            os.close(fd)
            fd = None
            # The database path is now an existing, private file. Opening in
            # SQLite mode=rw must never silently recreate it.
            with closing(sqlite3.connect(
                path.absolute().as_uri() + "?mode=rw",
                uri=True, timeout=5, isolation_level=None,
            )) as conn:
                conn.execute("PRAGMA busy_timeout=5000")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "CREATE TABLE agent_nonces "
                    "(node_id TEXT NOT NULL, nonce TEXT NOT NULL, "
                    "expires_at INTEGER NOT NULL, PRIMARY KEY(node_id,nonce))"
                )
                conn.execute(
                    "CREATE TABLE replay_store_identity "
                    "(node_id TEXT NOT NULL PRIMARY KEY)"
                )
                conn.execute(
                    "INSERT INTO replay_store_identity(node_id) VALUES (?)",
                    (node_id,),
                )
                conn.execute(f"PRAGMA user_version={REPLAY_SCHEMA_VERSION}")
                conn.commit()
            # Durable initial path creation: flush the containing directory.
            directory = os.open(
                path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except (sqlite3.Error, OSError) as exc:
            raise AgentAuthUnavailable("Replay store bootstrap unavailable") from exc
        finally:
            if fd is not None:
                os.close(fd)

    def _open(self) -> sqlite3.Connection:
        _private_parent(self.database)
        # No O_CREAT, CREATE TABLE IF NOT EXISTS or silent fallback in any
        # request path. SQLite mode=rw refuses missing files even under races.
        try:
            entry = self.database.lstat()
            if (
                not stat.S_ISREG(entry.st_mode)
                or entry.st_uid != os.geteuid()
                or stat.S_IMODE(entry.st_mode) != 0o600
                or entry.st_nlink != 1
            ):
                raise AgentAuthUnavailable("Unsafe replay database permissions")
            conn = sqlite3.connect(
                self.database.absolute().as_uri() + "?mode=rw",
                uri=True, timeout=5, isolation_level=None,
            )
            try:
                conn.execute("PRAGMA busy_timeout=5000")
                if conn.execute("PRAGMA user_version").fetchone() != (REPLAY_SCHEMA_VERSION,):
                    raise AgentAuthUnavailable("Replay database schema untrusted")
                conn.execute("SELECT node_id,nonce,expires_at FROM agent_nonces LIMIT 0")
                conn.execute("SELECT node_id FROM replay_store_identity LIMIT 0")
                # Directory entry must still point to the opened DB. A local
                # adversarial same-UID writer remains outside this draft's
                # production trust model; do not treat this as full openat2.
                after = self.database.lstat()
                if (entry.st_dev, entry.st_ino) != (after.st_dev, after.st_ino):
                    raise AgentAuthUnavailable("Replay database replaced")
            except BaseException:
                conn.close()
                raise
            return conn
        except (sqlite3.Error, OSError) as exc:
            raise AgentAuthUnavailable("Replay database unavailable") from exc

    def register(self, node_id: str, nonce: str, now: int) -> bool:
        if not _NODE_ID.fullmatch(node_id) or not _NONCE.fullmatch(nonce):
            return False
        with closing(self._open()) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                saved = conn.execute(
                    "SELECT node_id FROM replay_store_identity"
                ).fetchall()
                if saved != [(node_id,)]:
                    conn.rollback()
                    raise AgentAuthUnavailable("Replay store paired identity mismatch")
                conn.execute("DELETE FROM agent_nonces WHERE expires_at < ?", (now,))
                count = conn.execute("SELECT COUNT(*) FROM agent_nonces").fetchone()[0]
                if count >= self.max_entries:
                    conn.rollback()
                    return False
                conn.execute(
                    "INSERT INTO agent_nonces(node_id,nonce,expires_at) VALUES(?,?,?)",
                    (node_id, nonce, now + 2 * self.skew_seconds),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
            except sqlite3.Error as exc:
                conn.rollback()
                raise AgentAuthUnavailable("Replay transaction failed") from exc


def _http_target(request: Request) -> str:
    path = request.scope.get("raw_path")
    query = request.scope.get("query_string", b"")
    if not isinstance(path, bytes) or not isinstance(query, bytes):
        raise AgentAuthUnavailable("HTTP target missing")
    # ASGI transport implementations differ: some provide raw_path WITH
    # its query string as well as scope.query_string. Require byte-identical
    # query values and canonicalize exactly once; never silently discard an
    # inconsistent value that could produce a signature-confusion bypass.
    if b"?" in path:
        raw_path, embedded_query = path.split(b"?", 1)
        if embedded_query != query:
            raise AgentAuthUnavailable("Conflicting HTTP query representations")
        path = raw_path
    try:
        return (path + (b"?" + query if query else b"")).decode("ascii")
    except UnicodeDecodeError as exc:
        raise AgentAuthUnavailable("HTTP target invalid") from exc


def verify_agent_envelope(
    *, identity_path: str, replay_path: str, method: str,
    target: str, body: bytes, headers: dict[str, str], now: int | None = None,
) -> bool:
    node_id, secret = read_identity(identity_path)
    replay = DurableNonceStore(replay_path)
    return node_auth.verify_request(
        secret=secret, node_id=node_id, method=method, target=target,
        body=body, headers=headers, replay=replay, now=now,
    )


async def require_agent_auth(request: Request) -> None:
    """Uniform dependency: protect ALL /api/agent paths in strict mode."""
    if settings.smite_agent_auth_mode == "legacy":
        return

    length = request.headers.get("content-length")
    if length is not None:
        try:
            length_num = int(length)
        except ValueError as exc:
            raise HTTPException(400, "Invalid content length") from exc
        if length_num < 0 or length_num > MAX_REQUEST_BODY:
            raise HTTPException(413, "Request body too large")
    body = await request.body()
    if len(body) > MAX_REQUEST_BODY:
        raise HTTPException(413, "Request body too large")

    try:
        accepted = await run_in_threadpool(
            verify_agent_envelope,
            identity_path=settings.smite_agent_identity_path,
            replay_path=settings.smite_agent_replay_db,
            method=request.method,
            target=_http_target(request),
            body=body, headers=dict(request.headers),
        )
    except AgentAuthUnavailable as exc:
        raise HTTPException(503, "Agent authentication unavailable") from exc
    except (node_auth.NodeAuthError, ValueError) as exc:
        raise HTTPException(401, "Unauthorized Agent request") from exc
    if not accepted:
        raise HTTPException(401, "Unauthorized Agent request")
