"""Database-backed, one-use Smite Node pairing service (inert foundation).

No FastAPI routes import or call this module yet. It is deliberately separate
from the legacy unauthenticated /api/nodes flow until a coordinated migration.

This code requires a *dedicated* persistent Fernet master key, independent of
Smite's admin JWT secret. Never store the master key in the SQLite database.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
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
    """Never re-create an absent Panel DB during authentication or pairing."""
    path = Path(database_path)
    if path.is_symlink() or not path.is_file():
        raise PairingDenied("Existing Panel database required")
    try:
        connection = sqlite3.connect(
            path.absolute().as_uri() + "?mode=rw",
            uri=True, timeout=15, isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=15000")
        return connection
    except sqlite3.Error as exc:
        raise PairingDenied("Panel database unavailable") from exc


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
    """Atomic irreversible old-Node revocation + outstanding-code cancellation.

    A revoked Node ID can NEVER receive a fresh secret through issue_code.
    Recovery uses a NEW admin-approved Node ID plus fresh identity/replay
    storage; no silent in-place same-ID key replacement is offered.
    This function NEVER creates a missing Panel database.
    """
    _validate_node_id(node_id)
    path = Path(database_path)
    if path.is_symlink() or not path.is_file():
        raise PairingDenied("Existing Panel database required")
    try:
        with closing(sqlite3.connect(
            path.absolute().as_uri() + "?mode=rw",
            timeout=15, isolation_level=None, uri=True,
        )) as conn:
            conn.execute("PRAGMA busy_timeout=15000")
            conn.execute("BEGIN IMMEDIATE")
            try:
                current = _now(now)
                result = conn.execute(
                    "UPDATE smite_node_identities SET revoked_at = ? "
                    "WHERE node_id = ? AND revoked_at IS NULL",
                    (current, node_id),
                )
                if result.rowcount != 1:
                    conn.rollback()
                    return False
                # In the SAME transaction, consume even stale or replayed
                # outstanding pairing codes for this irrevocably old Node.
                conn.execute(
                    "UPDATE smite_node_pairing_codes SET consumed_at = ? "
                    "WHERE node_id = ? AND consumed_at IS NULL",
                    (current, node_id),
                )
                conn.commit()
                return True
            except BaseException:
                conn.rollback()
                raise
    except sqlite3.Error as exc:
        raise PairingDenied("Cannot atomically revoke Node credential") from exc


def main(argv: list[str] | None = None) -> int:
    """Explicit offline one-way operator command; NEVER called from routes."""
    parser = argparse.ArgumentParser(
        description="Offline revoke old paired Node; NEVER a same-ID key rotation"
    )
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--confirm-signed-panel-and-node-paused", action="store_true")
    parser.add_argument("--confirm-reviewed-panel-db-backup", action="store_true")
    parser.add_argument("--confirm-replacement-uses-new-node-id", action="store_true")
    args = parser.parse_args(argv)
    if not all((
        args.confirm_signed_panel_and_node_paused,
        args.confirm_reviewed_panel_db_backup,
        args.confirm_replacement_uses_new_node_id,
    )):
        print("HOLD: Maintenance pause, reviewed backup and new UUID approval required",
              file=sys.stderr)
        return 2
    path = args.database
    try:
        if not path.is_absolute() or ".." in path.parts:
            raise PairingDenied("Absolute Panel DB path required")
        meta = path.lstat()
        parent = path.parent.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid()
                or meta.st_nlink != 1 or stat.S_IMODE(meta.st_mode) & 0o077
                or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) & 0o077):
            raise PairingDenied("Panel DB and directory must be private and owned")
        if not revoke_node(path, node_id=args.node_id):
            raise PairingDenied("Old Node not active or already revoked")
    except (PairingDenied, OSError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2
    print("OLD_PANEL_NODE_ID=REVOKED")
    print("OUTSTANDING_PAIRING_CODES=INVALIDATED")
    print("SAME_NODE_ID_REKEY=FORBIDDEN")
    print("OLD_NODE_SIGNED_TRAFFIC_RESUMPTION=NOT_AUTHORIZED")
    print("NODE_AGENT_STILL_REQUIRES_OFFLINE_PAUSE_AND_KEY_RETIREMENT=YES")
    print("FRESH_NODE_UUID_AND_REPLAY_ENROLLMENT=SEPARATE_OPERATOR_APPROVAL")
    print("RELEASE_OR_ACTIVATION_AUTHORIZED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
