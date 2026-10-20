"""Operator-only first provisioning of strict Agent replay SQLite.

No HTTP endpoint, startup hook, environment-mode change or recovery button.
The durable enrollment marker is intentionally stored with the paired identity
on a separate persistent directory from the replay DB. It is created BEFORE
SQLite initialization, and is NEVER automatically deleted if bootstrap fails.
A missing DB after enrollment cannot be mistaken for a first install while
the independent identity/enrollment directory survives.

Not a defense against root compromise, lost *both* identity and replay volumes,
or rollback of same-Node replay history from an old snapshot.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import stat
import sys

from app.agent_auth import (
    AgentAuthUnavailable,
    DurableNonceStore,
    _private_parent,
    read_identity,
)


class ReplayEnrollmentHold(RuntimeError):
    """Fail closed, never print secrets or automatically repair replay state."""


def _require_abs_private(path: Path, name: str) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ReplayEnrollmentHold(f"{name}: an absolute private path is required")
    try:
        _private_parent(path)
    except AgentAuthUnavailable as exc:
        raise ReplayEnrollmentHold(f"{name}: private 0700 owner directory required") from exc


def _exists(path: Path) -> bool:
    return path.is_symlink() or path.exists()


def _create_marker(marker: Path, node_id: str, replay: Path) -> None:
    # A marker records no secret or previously used nonce. It lives alongside
    # the paired identity and must survive deletion of the replay DB mount.
    document = {
        "schema": 1, "node_id": node_id,
        "replay_database": str(replay), "status": "ENROLLMENT_STARTED",
    }
    content = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = None
    try:
        fd = os.open(
            marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        parent_fd = os.open(
            marker.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise ReplayEnrollmentHold("Cannot durably record one-time enrollment") from exc
    finally:
        if fd is not None:
            os.close(fd)


def provision_once(*, identity_path: str | Path, replay_path: str | Path) -> None:
    """Explicit offline first enrollment ONLY. Refuse all repeat attempts.

    Requires an already paired private Node identity file plus separate,
    pre-mounted durable private identity and replay directories.
    No mkdir, no overwrite, no renaming damaged data, no auto-retry.
    """
    identity = Path(identity_path)
    replay = Path(replay_path)
    _require_abs_private(identity, "Paired identity")
    _require_abs_private(replay, "Replay database")
    if identity.parent == replay.parent or identity == replay:
        raise ReplayEnrollmentHold("Identity and replay DB require separate private directories")
    marker = identity.parent / "replay-enrollment.json"
    if _exists(marker):
        raise ReplayEnrollmentHold("Replay enrollment already started: refuse re-bootstrap")
    if _exists(replay):
        raise ReplayEnrollmentHold("Replay database already exists: refuse re-bootstrap")
    try:
        node_id, first_secret = read_identity(identity)
    except AgentAuthUnavailable as exc:
        raise ReplayEnrollmentHold("Valid, previously paired identity is required") from exc
    # Creating the durable independent marker FIRST means interrupted
    # initialization remains quarantined, rather than silently retried.
    _create_marker(marker, node_id, replay)
    try:
        DurableNonceStore.initialize_new(replay, node_id)
        # Confirm no pairing identity replacement occurred while provisioning.
        after_id, after_secret = read_identity(identity)
        if after_id != node_id or after_secret != first_secret:
            raise ReplayEnrollmentHold("Paired identity changed during enrollment")
        with closing(DurableNonceStore(replay)._open()) as conn:
            saved = conn.execute("SELECT node_id FROM replay_store_identity").fetchall()
            if saved != [(node_id,)]:
                raise ReplayEnrollmentHold("Replay database identity mismatch")
    except (AgentAuthUnavailable, OSError) as exc:
        # NEVER remove marker/db on error: a manual trusted review is needed.
        raise ReplayEnrollmentHold("Replay initialization unavailable; quarantine and review") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline one-time replay DB provisioning; NEVER run for restore"
    )
    parser.add_argument("--identity", required=True)
    parser.add_argument("--replay-db", required=True)
    parser.add_argument(
        "--confirm-first-provision", action="store_true",
        help="Explicit one-time operator admission; not recovery or key rotation",
    )
    args = parser.parse_args(argv)
    if not args.confirm_first_provision:
        print("HOLD: Explicit first-provision confirmation required", file=sys.stderr)
        return 2
    try:
        provision_once(identity_path=args.identity, replay_path=args.replay_db)
    except (ReplayEnrollmentHold, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2
    print("REPLAY_DB_FIRST_ENROLLMENT=PROVISIONED")
    print("ENROLLMENT_MARKER=PERSISTENT_IN_IDENTITY_DIRECTORY")
    print("SIGNED_TRAFFIC_ACTIVATION=NOT_AUTHORIZED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
