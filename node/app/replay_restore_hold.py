"""Offline, one-way quarantine of a Node after replay-store restore/loss.

Operator must stop ALL signed traffic and review paired identity/DB first.
This tool ONLY writes a durable 0600 hold beside the independent paired
identity; it never restores/reinitializes SQLite, rotates keys, unblocks
traffic or changes services. Re-running is an error, not an unlock.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from app.agent_auth import (AgentAuthUnavailable, RESTORE_HOLD_NAME,
                            read_identity, _private_parent)
from app.replay_enrollment import ReplayEnrollmentHold, _require_abs_private


def quarantine(*, identity_path: str | Path, replay_path: str | Path) -> None:
    identity = Path(identity_path)
    replay = Path(replay_path)
    _require_abs_private(identity, "Paired identity")
    _require_abs_private(replay, "Replay database")
    if replay.parent == identity.parent:
        raise ReplayEnrollmentHold("Independent identity/replay directories required")

    node_id, _ = read_identity(identity)
    enrolled = identity.parent / "replay-enrollment.json"
    # An operator must not invent a recovery identity/path: read the
    # original first-enrollment record, without following a symlink.
    try:
        fd = os.open(enrolled, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            meta = os.fstat(f.fileno())
            if (not stat.S_ISREG(meta.st_mode)
                    or meta.st_uid != os.geteuid()
                    or stat.S_IMODE(meta.st_mode) != 0o600
                    or meta.st_nlink != 1 or meta.st_size > 4096):
                raise ReplayEnrollmentHold("Unsafe original enrollment marker")
            record = json.loads(f.read(4097))
    except (OSError, ValueError, UnicodeError, TypeError) as exc:
        raise ReplayEnrollmentHold("Original enrollment unavailable; do not restore") from exc
    if (not isinstance(record, dict)
            or record.get("schema") != 1
            or record.get("node_id") != node_id
            or record.get("replay_database") != str(replay)
            or record.get("status") != "ENROLLMENT_STARTED"):
        raise ReplayEnrollmentHold("Original enrollment identity/path mismatch")

    hold = identity.parent / RESTORE_HOLD_NAME
    body = json.dumps({
        "schema": 1, "node_id": node_id, "status": "QUARANTINED",
        "replay_database": str(replay),
    }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    try:
        fd = os.open(hold, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        directory = os.open(hold.parent, os.O_RDONLY
                            | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise ReplayEnrollmentHold("Could not persist replay restore HOLD") from exc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--identity", required=True)
    p.add_argument("--replay-db", required=True)
    p.add_argument("--confirm-offline-quarantine", action="store_true")
    opt = p.parse_args(argv)
    if not opt.confirm_offline_quarantine:
        print("HOLD: Explicit offline quarantine confirmation required", file=sys.stderr)
        return 2
    try:
        quarantine(identity_path=opt.identity, replay_path=opt.replay_db)
    except (ReplayEnrollmentHold, AgentAuthUnavailable, OSError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2
    print("REPLAY_RESTORE_QUARANTINE=ACTIVE")
    print("SIGNED_TRAFFIC_ALLOWED=NO")
    print("AUTOMATIC_RELEASE=NEVER")
    print("PAIRED_RECOVERY_APPROVAL=REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
