#!/usr/bin/env python3
"""Read-only, independently pinned recovery witness for an OLD revoked Node.

Creation is manual and OFFLINE *after* Panel revocation, with signers paused.
Verification requires a witness SHA256 from an INDEPENDENT trusted source,
NOT computed from the downloaded/restored witness under inspection.
No mutation of SQLite on verify. No restart, recovery, unlock or deployment.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys

_NODE_ID = re.compile(r"[A-Za-z0-9_-]{8,80}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")


class RecoveryHold(ValueError):
    pass


def _private_file(path: Path, *, limit: int | None = None) -> None:
    if not path.is_absolute() or ".." in path.parts or path.is_symlink():
        raise RecoveryHold("Absolute non-symlink private path required")
    try:
        entry, parent = path.lstat(), path.parent.lstat()
    except OSError as exc:
        raise RecoveryHold("Required state file unavailable") from exc
    if (not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.geteuid()
            or stat.S_IMODE(entry.st_mode) != 0o600 or entry.st_nlink != 1
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
            or (limit is not None and entry.st_size > limit)):
        raise RecoveryHold("State file or parent has unsafe permissions")


def _db_revoked(database: Path, node_id: str) -> int:
    if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
        raise RecoveryHold("Specific old Node UUID required")
    _private_file(database)
    try:
        with closing(sqlite3.connect(
            database.absolute().as_uri() + "?mode=ro", uri=True, timeout=5
        )) as conn:
            state = conn.execute(
                "SELECT revoked_at FROM smite_node_identities WHERE node_id=?",
                (node_id,),
            ).fetchall()
            if len(state) != 1 or type(state[0][0]) is not int or state[0][0] <= 0:
                raise RecoveryHold("Old Node key active or missing")
            open_codes = conn.execute(
                "SELECT COUNT(*) FROM smite_node_pairing_codes "
                "WHERE node_id=? AND consumed_at IS NULL", (node_id,),
            ).fetchone()
            if open_codes is None or open_codes[0] != 0:
                raise RecoveryHold("Outstanding old Node pairing codes")
            return state[0][0]
    except sqlite3.Error as exc:
        raise RecoveryHold("Revocation cannot be verified in Panel DB") from exc


def create_witness(*, database: Path, node_id: str, output: Path) -> str:
    stamp = _db_revoked(database, node_id)
    if (not output.is_absolute() or ".." in output.parts
            or output.parent == database.parent or output.is_symlink()):
        raise RecoveryHold("Witness must reside outside Panel DB directory")
    try:
        folder = output.parent.lstat()
        if (not stat.S_ISDIR(folder.st_mode) or folder.st_uid != os.geteuid()
                or stat.S_IMODE(folder.st_mode) != 0o700):
            raise RecoveryHold("Independent witness directory must be private")
        doc = {
            "schema": 1, "kind": "smite_panel_old_node_revocation_witness",
            "node_id": node_id, "revoked_at": stamp,
            "activation_allowed": False, "snapshot_restore_approved": False,
        }
        content = (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        parent_fd = os.open(output.parent, os.O_RDONLY
                            | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return hashlib.sha256(content).hexdigest()
    except OSError as exc:
        raise RecoveryHold("Unable to persist independent witness") from exc


def verify_witness(*, database: Path, node_id: str,
                   witness: Path, witness_sha256: str) -> None:
    if not isinstance(witness_sha256, str) or not _SHA256.fullmatch(witness_sha256):
        raise RecoveryHold("Independently trusted witness SHA256 required")
    _private_file(witness, limit=4096)
    raw = witness.read_bytes()
    if hashlib.sha256(raw).hexdigest() != witness_sha256:
        raise RecoveryHold("Witness SHA256 differs from operator trust anchor")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise RecoveryHold("Malformed independent witness") from exc
    if (not isinstance(doc, dict)
            or set(doc) != {"schema", "kind", "node_id", "revoked_at",
                            "activation_allowed", "snapshot_restore_approved"}
            or type(doc.get("schema")) is not int or doc["schema"] != 1
            or doc["kind"] != "smite_panel_old_node_revocation_witness"
            or doc.get("node_id") != node_id
            or type(doc.get("revoked_at")) is not int or doc["revoked_at"] <= 0
            or doc["activation_allowed"] is not False
            or doc["snapshot_restore_approved"] is not False):
        raise RecoveryHold("Untrusted witness contract")
    actual = _db_revoked(database, node_id)
    if actual != doc["revoked_at"]:
        raise RecoveryHold("Panel DB restore no longer matches revoked witness")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("operation", choices=["create", "verify"])
    p.add_argument("--database", type=Path, required=True)
    p.add_argument("--node-id", required=True)
    p.add_argument("--witness", type=Path, required=True)
    p.add_argument("--witness-sha256")
    p.add_argument("--confirm-signers-paused-and-backup-reviewed", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.operation == "create":
            if not args.confirm_signers_paused_and_backup_reviewed:
                raise RecoveryHold("Explicit stopped-signers/backup admission required")
            digest = create_witness(
                database=args.database, node_id=args.node_id, output=args.witness)
            print("INDEPENDENT_WITNESS_SHA256=" + digest)
            print("KEEP_SHA256_OUTSIDE_PANEL_DB_AND_BACKUP=YES")
        else:
            verify_witness(database=args.database, node_id=args.node_id,
                           witness=args.witness,
                           witness_sha256=args.witness_sha256 or "")
            print("REVOKED_NODE_SNAPSHOT_WITNESS=VERIFIED")
    except (RecoveryHold, OSError, TypeError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2
    print("NODE_SIGNERS_RESTART_ALLOWED=NO")
    print("RELEASE_OR_ACTIVATION_AUTHORIZED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
