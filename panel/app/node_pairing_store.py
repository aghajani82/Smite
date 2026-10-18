"""Database-backed, one-use Smite Node pairing service (inert foundation).

No FastAPI routes import or call this module yet. It is deliberately separate
from the legacy unauthenticated /api/nodes flow until a coordinated migration.

This code requires a *dedicated* persistent Fernet master key, independent of
Smite's admin JWT secret. Never store the master key in the SQLite database.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time

from cryptography.fernet import Fernet, InvalidToken


PAIRING_PREFIX = "smn1_"
MAX_PAIRING_TTL = 900
MIN_PAIRING_TTL = 60
_ID = re.compile(r"^[a-zA-Z0-9_-]{8,80}$")
_ROLE = frozenset(("iran", "foreign"))


class PairingDenied(ValueError):
    """Generic denial: caller must not reveal whether a code exists."""


@dataclass(frozen=True)
class EnrollmentCode:
    code: str  # Return once to authenticated admin; NEVER log or persist raw.
    node_id: str
    expires_at: int


@dataclass(frozen=True)
class NodeCredential:
    node_id: str
    # Return once to Node over strictly verified TLS; never serialize in admin APIs.
    secret: str


def _fernet(master_key: bytes | str) -> Fernet:
    if not master_key:
        raise PairingDenied("A dedicated persistent master key is required")
    try:
        return Fernet(master_key)
    except (ValueError, TypeError) as exc:
        raise PairingDenied("Invalid dedicated master key") from exc


def _now(value: int | None) -> int:
    return int(time.time()) if value is None else int(value)


def _validate_node_id(node_id: str) -> None:
    if not isinstance(node_id, str) or not _ID.fullmatch(node_id):
        raise PairingDenied("Invalid node ID")


def _hash_code(code: str) -> str:
    if not isinstance(code, str) or len(code) > 128 or not code.startswith(PAIRING_PREFIX):
        raise PairingDenied("Pairing denied")
    return hashlib.sha256(b"smite-node-pairing-v1\x00" + code.encode("ascii")).hexdigest()


def _open_database(database_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(database_path), timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=15000")
    return connection


def _matching_registered_node(conn: sqlite3.Connection, node_id: str, role: str) -> bool:
    """Must target an admin-selected, pre-existing Node record, not arbitrary ID."""
    row = conn.execute(
        "SELECT metadata FROM nodes WHERE id = ?", (node_id,)
    ).fetchone()
    if row is None:
        return False
    try:
        metadata = json.loads(row["metadata"] or "{}")
        return isinstance(metadata, dict) and metadata.get("role") == role
    except (json.JSONDecodeError, TypeError):
        return False


def initialize_schema(database_path: str | Path) -> None:
    """Explicit opt-in migration; never invoked at import or app startup."""
    with closing(_open_database(database_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if not conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nodes'"
            ).fetchone():
                raise PairingDenied("Smite nodes table must exist before enrollment")

            conn.execute(
                """CREATE TABLE IF NOT EXISTS smite_node_pairing_codes (
                    code_hash TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    node_role TEXT NOT NULL CHECK(node_role IN ('iran','foreign')),
                    issued_by_admin_id TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS smite_node_identities (
                    node_id TEXT PRIMARY KEY,
                    node_role TEXT NOT NULL CHECK(node_role IN ('iran','foreign')),
                    encrypted_secret TEXT NOT NULL,
                    paired_at INTEGER NOT NULL,
                    revoked_at INTEGER
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_smite_pairing_expiry "
                "ON smite_node_pairing_codes (expires_at)"
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def issue_code(
    database_path: str | Path, *, master_key: bytes | str,
    node_id: str, role: str, admin_id: str,
    ttl_seconds: int = 600, now: int | None = None
) -> EnrollmentCode:
    """Issue a scoped, expiring code for an admin-approved *existing* Node."""
    _fernet(master_key)
    _validate_node_id(node_id)
    if role not in _ROLE or not admin_id or not isinstance(admin_id, str):
        raise PairingDenied("Invalid approval scope")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not (
        MIN_PAIRING_TTL <= ttl_seconds <= MAX_PAIRING_TTL
    ):
        raise PairingDenied("Unsupported pairing expiry")

    code = PAIRING_PREFIX + secrets.token_urlsafe(32)  # 256 bits of entropy
    hashed = _hash_code(code)
    current = _now(now)
    with closing(_open_database(database_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if not _matching_registered_node(conn, node_id, role):
                raise PairingDenied("Node does not match approved role")
            if conn.execute(
                "SELECT 1 FROM smite_node_identities WHERE node_id = ?", (node_id,)
            ).fetchone():
                raise PairingDenied("Node already paired; use separate key rotation")

            # Invalidate outstanding codes for this exact Node (no accidental
            # concurrent active pairing codes for a single identity).
            conn.execute(
                "UPDATE smite_node_pairing_codes SET consumed_at = ? "
                "WHERE node_id = ? AND consumed_at IS NULL",
                (current, node_id),
            )
            conn.execute(
                "INSERT INTO smite_node_pairing_codes "
                "(code_hash,node_id,node_role,issued_by_admin_id,issued_at,expires_at) "
                "VALUES (?,?,?,?,?,?)",
                (hashed, node_id, role, admin_id, current, current + ttl_seconds),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return EnrollmentCode(code=code, node_id=node_id, expires_at=current + ttl_seconds)


def redeem_code(
    database_path: str | Path, *, master_key: bytes | str,
    code: str, node_id: str, role: str, now: int | None = None
) -> NodeCredential:
    """Consume a pairing code atomically, binding one durable node credential.

    The server encrypts the Node secret at rest using an independent master.
    An API adapter must return it ONLY once, after verifying TLS origin.
    """
    cipher = _fernet(master_key)
    _validate_node_id(node_id)
    if role not in _ROLE:
        raise PairingDenied("Pairing denied")
    try:
        code_hash = _hash_code(code)
    except (UnicodeEncodeError, PairingDenied) as exc:
        raise PairingDenied("Pairing denied") from exc

    current = _now(now)
    with closing(_open_database(database_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT node_id,node_role,expires_at,consumed_at "
                "FROM smite_node_pairing_codes WHERE code_hash = ?",
                (code_hash,),
            ).fetchone()
            if (
                row is None or row["consumed_at"] is not None
                or current >= row["expires_at"]
                or row["node_id"] != node_id or row["node_role"] != role
                or not _matching_registered_node(conn, node_id, role)
            ):
                raise PairingDenied("Pairing denied")
            if conn.execute(
                "SELECT 1 FROM smite_node_identities WHERE node_id = ?", (node_id,)
            ).fetchone():
                raise PairingDenied("Pairing denied")

            secret = secrets.token_hex(32)  # 256-bit per-node HMAC secret
            encrypted = cipher.encrypt(secret.encode("ascii")).decode("ascii")
            conn.execute(
                "INSERT INTO smite_node_identities "
                "(node_id,node_role,encrypted_secret,paired_at) "
                "VALUES (?,?,?,?)",
                (node_id, role, encrypted, current),
            )
            result = conn.execute(
                "UPDATE smite_node_pairing_codes SET consumed_at = ? "
                "WHERE code_hash = ? AND consumed_at IS NULL",
                (current, code_hash),
            )
            if result.rowcount != 1:
                raise PairingDenied("Pairing denied")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return NodeCredential(node_id=node_id, secret=secret)


def get_active_secret(
    database_path: str | Path, *, master_key: bytes | str, node_id: str
) -> bytes:
    """For authenticated internal Panel→Node requests, never public responses."""
    cipher = _fernet(master_key)
    _validate_node_id(node_id)
    with closing(_open_database(database_path)) as conn:
        row = conn.execute(
            "SELECT encrypted_secret,revoked_at FROM smite_node_identities "
            "WHERE node_id = ?", (node_id,),
        ).fetchone()
        if row is None or row["revoked_at"] is not None:
            raise PairingDenied("Unknown or revoked Node")
        try:
            return cipher.decrypt(row["encrypted_secret"].encode("ascii"))
        except (InvalidToken, ValueError) as exc:
            raise PairingDenied("Cannot decrypt Node credential") from exc


def revoke_node(
    database_path: str | Path, *, node_id: str, now: int | None = None
) -> bool:
    """Atomic revocation; future credential reads must fail."""
    _validate_node_id(node_id)
    with closing(_open_database(database_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            result = conn.execute(
                "UPDATE smite_node_identities SET revoked_at = ? "
                "WHERE node_id = ? AND revoked_at IS NULL",
                (_now(now), node_id),
            )
            conn.commit()
            return result.rowcount == 1
        except Exception:
            conn.rollback()
            raise
