"""Explicit, default-inert SQLite admission for the Foreign install trial.

Never run on application import/startup. Backups are SQLite online snapshots
(WAL-aware), private and no-overwrite; no automatic restore of live identities.
Rollback of an *active* enrollment requires a separate audited recovery plan.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import fcntl
from itertools import zip_longest
import os
from pathlib import Path
import sqlite3
import stat
import tempfile

from app import foreign_install_grants
from app.config import settings

CONFIRM = "PREPARE-FOREIGN-INSTALL-TRIAL-SCHEMA"
BACKUP_SUFFIX = ".u-opti-pre-foreign-install-v1.bak"
BASE_CHECKS = (
    "SELECT id,name,metadata FROM nodes LIMIT 0",
    "SELECT node_id,node_role,encrypted_secret,paired_at,revoked_at FROM smite_node_identities LIMIT 0",
    "SELECT code_hash,node_id,consumed_at FROM smite_node_pairing_codes LIMIT 0",
    "SELECT node_id,nonce,expires_at FROM smite_node_inbound_nonces LIMIT 0",
)
TRIAL_CHECKS = (
    "SELECT code_hash,node_id,node_name,origin,control_url,issued_by,issued_at,expires_at,consumed_at,revoked_at FROM smite_foreign_install_grants LIMIT 0",
    "SELECT node_id,node_name,origin,control_url,grant_hash,approved_at FROM smite_foreign_install_origins LIMIT 0",
)


class AdmissionHold(RuntimeError):
    pass


def deny():
    raise AdmissionHold("Foreign installation schema admission HOLD")


def regular(path: Path, *, private: bool = False):
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        deny()
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022
            or (private and stat.S_IMODE(info.st_mode) != 0o600)):
        deny()


def checked_db(path) -> Path:
    # The real Panel ships DB_PATH=./data/smite.db inside its working
    # directory. Admit that relative setting, but never follow any symlink or
    # parent traversal after resolving it to an absolute path.
    requested = Path(path)
    if ".." in requested.parts:
        deny()
    candidate = requested.absolute()
    try:
        if candidate.resolve(strict=True) != candidate or candidate.parent.is_symlink():
            deny()
    except (OSError, RuntimeError):
        deny()
    regular(candidate)
    return candidate


def readonly(path: Path):
    return sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=8)


def inspect(database_path) -> str:
    """Return MISSING or READY; refuse partially migrated or corrupt schemas."""
    db = checked_db(database_path)
    try:
        with closing(readonly(db)) as conn:
            for query in BASE_CHECKS:
                conn.execute(query)
            if conn.execute("PRAGMA quick_check").fetchone() != ("ok",):
                deny()
            names = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('smite_foreign_install_grants','smite_foreign_install_origins')")}
            if not names:
                return "MISSING"
            if names != {"smite_foreign_install_grants", "smite_foreign_install_origins"}:
                deny()
            for query in TRIAL_CHECKS:
                conn.execute(query)
            return "READY"
    except sqlite3.Error:
        deny()


def _backup_path(db):
    return db.with_name(db.name + BACKUP_SUFFIX)


def _verify_retry_snapshot(db: Path, backup: Path) -> None:
    """Authorize reuse only when the prior backup still covers the full DB."""
    regular(backup, private=True)
    if inspect(backup) != "MISSING":
        deny()
    with closing(readonly(db)) as live, closing(readonly(backup)) as saved:
        live.execute("BEGIN")
        saved.execute("BEGIN")
        # SQLite's logical dump compares schema and data without relying on
        # page layout, journals or timestamps. A drifted DB needs review.
        for current, previous in zip_longest(live.iterdump(), saved.iterdump()):
            if current != previous:
                deny()


def _save_snapshot(db: Path):
    backup = _backup_path(db)
    if os.path.lexists(backup):
        deny()
    descriptor, temporary = tempfile.mkstemp(prefix=".u-opti-foreign-backup-", dir=db.parent)
    os.close(descriptor)
    try:
        with closing(readonly(db)) as source, closing(
            sqlite3.connect(temporary, timeout=15)
        ) as target:
            source.backup(target)
            if target.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
                deny()
        os.chmod(temporary, 0o600)
        with closing(readonly(Path(temporary))) as copy:
            if copy.execute("PRAGMA quick_check").fetchone() != ("ok",):
                deny()
            for query in BASE_CHECKS:
                copy.execute(query)
        with open(temporary, "rb") as item:
            os.fsync(item.fileno())
        # No rename/overwrite race: hard-link only to a still-unoccupied name.
        os.link(temporary, backup, follow_symlinks=False)
    finally:
        os.unlink(temporary)
    regular(backup, private=True)


def migrate(database_path, *, confirm: str):
    """Explicit additive schema installation; read-only inspection on retry."""
    if confirm != CONFIRM:
        deny()
    db = checked_db(database_path)
    directory_fd = os.open(db.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # Serialize cooperating migration attempts before checking schema or backup.
        fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if inspect(db) == "READY":
            return "ALREADY_READY"
        backup = _backup_path(db)
        if not os.path.lexists(backup):
            _save_snapshot(db)
        _verify_retry_snapshot(db, backup)
        os.fsync(directory_fd)
        foreign_install_grants.initialize_schema(db)
        if inspect(db) != "READY":
            deny()
        return "READY"
    except (sqlite3.Error, ValueError, OSError) as exc:
        raise AdmissionHold("Foreign installation migration HOLD; retain backup") from exc
    finally:
        os.close(directory_fd)


def main():
    parser = argparse.ArgumentParser(description="Explicit Foreign installation trial migration")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--review", action="store_true")
    mode.add_argument("--migrate", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    try:
        # Never permit migration on legacy/unsigned Panel. Flags remain OFF.
        if (settings.db_type != "sqlite" or settings.smite_node_registration_mode != "signed"
                or settings.smite_panel_agent_auth_mode != "signed"
                or not settings.smite_node_pairing_preview_enabled
                or not settings.smite_node_pairing_master_key):
            deny()
        if args.review:
            print("FOREIGN_INSTALL_SCHEMA=" + inspect(settings.db_path))
        else:
            print("FOREIGN_INSTALL_SCHEMA=" + migrate(settings.db_path, confirm=args.confirm))
        print("FOREIGN_INSTALL_FLAGS=UNCHANGED")
        print("RUNTIME_AND_GATEWAY=UNCHANGED")
    except (AdmissionHold, OSError, ValueError, sqlite3.Error):
        print("FOREIGN_INSTALL_SCHEMA=HOLD")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
