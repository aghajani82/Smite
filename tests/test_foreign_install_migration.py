"""Foreign SQLite migration: offline-only, no imported startup side effects."""
from pathlib import Path
import importlib
import fcntl
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))
from app import node_pairing_store as pairing
from app import foreign_install_migration as m


class Migration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "smite.db"
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE nodes (id TEXT PRIMARY KEY, name TEXT, metadata TEXT)")
            conn.execute("INSERT INTO nodes VALUES ('foreign-node-1234','node-kh','{}')")
        pairing.initialize_schema(self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE smite_node_inbound_nonces "
                         "(node_id TEXT, nonce TEXT, expires_at INTEGER,"
                         " PRIMARY KEY (node_id, nonce))")
        self.backup = self.root / ("smite.db" + m.BACKUP_SUFFIX)

    def tables(self, path):
        with sqlite3.connect(path) as conn:
            return {name for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def test_explicit_migration_snapshot_and_idempotence(self):
        self.assertEqual(m.inspect(self.db), "MISSING")
        self.assertFalse(self.backup.exists())
        self.assertEqual(m.migrate(self.db, confirm=m.CONFIRM), "READY")
        self.assertEqual(m.inspect(self.db), "READY")
        self.assertTrue(self.backup.is_file())
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.backup.stat().st_nlink, 1)
        self.assertEqual(self.tables(self.db)-self.tables(self.backup),
                         {"smite_foreign_install_grants","smite_foreign_install_origins"})
        with sqlite3.connect(self.backup) as conn:
            self.assertEqual(conn.execute("SELECT name FROM nodes WHERE id='foreign-node-1234'").fetchone()[0], "node-kh")
        original = self.backup.read_bytes()
        self.assertEqual(m.migrate(self.db, confirm=m.CONFIRM), "ALREADY_READY")
        self.assertEqual(self.backup.read_bytes(), original)

    def test_real_panel_relative_db_path_supported(self):
        # The shipped Panel uses DB_PATH=./data/smite.db from its working dir.
        current = Path.cwd()
        try:
            os.chdir(self.root)
            self.assertEqual(m.inspect("./smite.db"), "MISSING")
            self.assertEqual(m.migrate("./smite.db", confirm=m.CONFIRM), "READY")
            self.assertEqual(m.inspect("./smite.db"), "READY")
        finally:
            os.chdir(current)

    def test_parent_symlink_and_traversal_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(m.AdmissionHold):
            m.inspect(alias / "smite.db")
        with self.assertRaises(m.AdmissionHold):
            m.inspect(self.root / "one" / ".." / "smite.db")
        self.assertFalse(self.backup.exists())

    def test_wrong_confirmation_never_backups_or_migrates(self):
        with self.assertRaises(m.AdmissionHold):
            m.migrate(self.db, confirm="NO")
        self.assertEqual(m.inspect(self.db), "MISSING")
        self.assertFalse(self.backup.exists())

    def test_import_has_no_implicit_migration(self):
        importlib.reload(m)
        self.assertEqual(m.inspect(self.db), "MISSING")
        self.assertFalse(self.backup.exists())

    def test_existing_snapshot_refuses_new_migration(self):
        self.backup.write_text("not a SQLite snapshot")
        self.backup.chmod(0o600)
        with self.assertRaises(m.AdmissionHold):
            m.migrate(self.db, confirm=m.CONFIRM)
        self.assertEqual(self.backup.read_text(), "not a SQLite snapshot")
        self.assertEqual(m.inspect(self.db), "MISSING")

    def test_symlink_and_hardlinked_db_refused(self):
        target = self.root / "link.db"
        target.symlink_to(self.db)
        with self.assertRaises(m.AdmissionHold): m.inspect(target)
        target.unlink()
        os.link(self.db, target)
        with self.assertRaises(m.AdmissionHold): m.inspect(self.db)
        target.unlink()
        self.assertEqual(m.inspect(self.db), "MISSING")

    def test_partial_schema_holds_without_writes(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE smite_foreign_install_grants (code_hash TEXT)")
        with self.assertRaises(m.AdmissionHold): m.inspect(self.db)
        with self.assertRaises(m.AdmissionHold): m.migrate(self.db, confirm=m.CONFIRM)
        self.assertFalse(self.backup.exists())

    def test_wrong_trial_columns_hold(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE smite_foreign_install_grants (code_hash TEXT)")
            conn.execute("CREATE TABLE smite_foreign_install_origins (node_id TEXT)")
        with self.assertRaises(m.AdmissionHold): m.inspect(self.db)
        self.assertFalse(self.backup.exists())

    def _fake_schema(self, *, weaken_grants=False, weaken_origins=False,
                     extra_index=False, trigger=False, extra_foreign_key=False):
        from app.foreign_install_grants import FOREIGN_INSTALL_DDL
        grants, origins = FOREIGN_INSTALL_DDL
        if weaken_grants:
            grants = grants.replace("code_hash TEXT PRIMARY KEY",
                                    "code_hash TEXT")
        if weaken_origins:
            origins = origins.replace("grant_hash TEXT NOT NULL UNIQUE",
                                      "grant_hash TEXT NOT NULL")
        if extra_foreign_key:
            origins = origins.replace(
                "approved_at INTEGER NOT NULL)",
                "approved_at INTEGER NOT NULL, "
                "FOREIGN KEY (node_id) REFERENCES nodes(id))")
        with sqlite3.connect(self.db) as conn:
            conn.execute(grants)
            conn.execute(origins)
            if extra_index:
                conn.execute(
                    "CREATE INDEX foreign_unreviewed_index ON "
                    "smite_foreign_install_grants(node_id)")
            if trigger:
                conn.execute("""CREATE TRIGGER foreign_unreviewed_trigger
                    AFTER INSERT ON smite_foreign_install_origins
                    BEGIN SELECT RAISE(ABORT, 'unexpected'); END""")

    def test_grant_primary_key_must_not_be_omitted_by_old_migration(self):
        self._fake_schema(weaken_grants=True)
        with self.assertRaises(m.AdmissionHold): m.inspect(self.db)
        with self.assertRaises(m.AdmissionHold):
            m.migrate(self.db, confirm=m.CONFIRM)
        self.assertFalse(self.backup.exists())
        self.assertIn("smite_foreign_install_grants", self.tables(self.db))

    def test_origin_grant_hash_must_remain_unique(self):
        self._fake_schema(weaken_origins=True)
        with self.assertRaises(m.AdmissionHold): m.inspect(self.db)
        with self.assertRaises(m.AdmissionHold):
            m.migrate(self.db, confirm=m.CONFIRM)
        self.assertFalse(self.backup.exists())

    def test_existing_foreign_tables_with_extra_index_hold(self):
        self._fake_schema(extra_index=True)
        with self.assertRaises(m.AdmissionHold): m.inspect(self.db)
        self.assertFalse(self.backup.exists())

    def test_existing_foreign_tables_with_trigger_hold(self):
        self._fake_schema(trigger=True)
        with self.assertRaises(m.AdmissionHold): m.inspect(self.db)
        self.assertFalse(self.backup.exists())

    def test_unreviewed_foreign_key_constraint_holds(self):
        self._fake_schema(extra_foreign_key=True)
        with self.assertRaises(m.AdmissionHold): m.inspect(self.db)
        self.assertFalse(self.backup.exists())

    def test_wrong_expiry_default_and_case_insensitive_grant_index_hold(self):
        from app.foreign_install_grants import FOREIGN_INSTALL_DDL
        grants, origins = FOREIGN_INSTALL_DDL
        for change in (
            ("expires_at INTEGER NOT NULL",
             "expires_at INTEGER NOT NULL DEFAULT 1"),
            ("code_hash TEXT PRIMARY KEY",
             "code_hash TEXT PRIMARY KEY COLLATE NOCASE"),
        ):
            with self.subTest(change=change):
                with sqlite3.connect(self.db) as conn:
                    conn.execute(grants.replace(*change))
                    conn.execute(origins)
                with self.assertRaises(m.AdmissionHold):
                    m.inspect(self.db)
                with self.assertRaises(m.AdmissionHold):
                    m.migrate(self.db, confirm=m.CONFIRM)
                self.assertFalse(self.backup.exists())
                with sqlite3.connect(self.db) as conn:
                    conn.execute("DROP TABLE smite_foreign_install_origins")
                    conn.execute("DROP TABLE smite_foreign_install_grants")

    def test_preexisting_backup_symlink_is_not_followed(self):
        original = self.root / "guard"
        original.write_text("guard")
        self.backup.symlink_to(original)
        with self.assertRaises(m.AdmissionHold): m.migrate(self.db, confirm=m.CONFIRM)
        self.assertEqual(original.read_text(), "guard")
        self.assertTrue(self.backup.is_symlink())

    def test_failed_schema_transaction_retains_backup_for_recovery(self):
        with patch.object(m.foreign_install_grants, "initialize_schema", side_effect=sqlite3.OperationalError()):
            with self.assertRaises(m.AdmissionHold):
                m.migrate(self.db, confirm=m.CONFIRM)
        self.assertEqual(m.inspect(self.db), "MISSING")
        self.assertTrue(self.backup.exists())
        original = self.backup.read_bytes()
        self.assertEqual(m.migrate(self.db, confirm=m.CONFIRM), "READY")
        self.assertEqual(self.backup.read_bytes(), original)

    def test_retry_refuses_database_changes_after_snapshot(self):
        m._save_snapshot(self.db)
        original = self.backup.read_bytes()
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE nodes SET name='changed'")
        with self.assertRaises(m.AdmissionHold):
            m.migrate(self.db, confirm=m.CONFIRM)
        self.assertEqual(m.inspect(self.db), "MISSING")
        self.assertEqual(self.backup.read_bytes(), original)

    def test_migration_holds_while_another_operation_owns_lock(self):
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(m.AdmissionHold):
                m.migrate(self.db, confirm=m.CONFIRM)
            self.assertFalse(self.backup.exists())
        finally:
            os.close(descriptor)

    def test_existing_pairing_identity_preserved(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("INSERT INTO smite_node_identities (node_id,node_role,encrypted_secret,paired_at) VALUES ('foreign-node-1234','foreign','ciphertext',12345)")
        self.assertEqual(m.migrate(self.db, confirm=m.CONFIRM), "READY")
        with sqlite3.connect(self.db) as conn:
            row = conn.execute("SELECT node_role,encrypted_secret,paired_at FROM smite_node_identities WHERE node_id='foreign-node-1234'").fetchone()
            self.assertEqual(row, ("foreign","ciphertext",12345))
        with sqlite3.connect(self.backup) as conn:
            self.assertEqual(conn.execute("SELECT encrypted_secret FROM smite_node_identities WHERE node_id='foreign-node-1234'").fetchone()[0], "ciphertext")

    def test_wal_online_snapshot_contains_committed_rows(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("INSERT INTO nodes VALUES ('another-node-1234','another','{}')")
        self.assertEqual(m.migrate(self.db, confirm=m.CONFIRM), "READY")
        with sqlite3.connect(self.backup) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],2)


if __name__=="__main__":
    unittest.main()
