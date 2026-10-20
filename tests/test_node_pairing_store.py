"""Offline integration tests for atomic, single-use Node pairing persistence.

Uses temporary SQLite only. No Smite services, HTTP endpoints, tunnel
commands, GitHub deployment, or VPS access.
"""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.fernet import Fernet


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "panel/app/node_pairing_store.py"
spec = importlib.util.spec_from_file_location("pairing_store_inert", PATH)
store = importlib.util.module_from_spec(spec)
# dataclass requires registering the dynamically imported module:
import sys
sys.modules[spec.name] = store
spec.loader.exec_module(store)


class PairingStoreTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.db = Path(self.work.name) / "smite.db"
        self.master = Fernet.generate_key()
        self.other_master = Fernet.generate_key()
        self.now = 1850000000
        self.ir = "aaaaaaaa-1111-2222-3333-444444444444"
        self.kh = "bbbbbbbb-1111-2222-3333-444444444444"

        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE nodes (id TEXT PRIMARY KEY, name TEXT, metadata TEXT)")
            conn.execute(
                "INSERT INTO nodes (id,name,metadata) VALUES (?,?,?)",
                (self.ir, "node-ir", json.dumps({"role": "iran", "node_name": "node-ir"})),
            )
            conn.execute(
                "INSERT INTO nodes (id,name,metadata) VALUES (?,?,?)",
                (self.kh, "node-kh", json.dumps({"role": "foreign", "node_name": "node-kh"})),
            )
        store.initialize_schema(self.db)

    def issue(self, *, node_id=None, role="iran", **kwargs):
        return store.issue_code(
            self.db, master_key=self.master,
            node_id=node_id or self.ir, role=role,
            admin_id="admin-12345678", now=self.now, **kwargs
        )

    def redeem(self, code, *, node_id=None, role="iran", now=None, **kwargs):
        return store.redeem_code(
            self.db, master_key=self.master,
            code=code, node_id=node_id or self.ir, role=role,
            now=self.now + 1 if now is None else now, **kwargs
        )

    def test_pairing_success_identity_scope_and_encrypted_storage(self):
        approval = self.issue()
        credential = self.redeem(approval.code)
        self.assertEqual(credential.node_id, self.ir)
        self.assertEqual(len(credential.secret), 64)
        self.assertEqual(
            store.get_active_secret(self.db, master_key=self.master, node_id=self.ir),
            credential.secret.encode("ascii"),
        )
        raw = self.db.read_bytes()
        self.assertNotIn(approval.code.encode(), raw)
        self.assertNotIn(credential.secret.encode(), raw)
        with self.assertRaises(store.PairingDenied):
            store.get_active_secret(self.db, master_key=self.other_master, node_id=self.ir)
        with self.assertRaises(store.PairingDenied):
            self.redeem(approval.code)

    def test_offline_master_recovers_both_active_and_revoked_rows_without_modifying_db(self):
        self.redeem(self.issue().code)
        self.redeem(self.issue(node_id=self.kh, role="foreign").code,
                    node_id=self.kh, role="foreign")
        self.assertTrue(store.revoke_node(self.db, node_id=self.ir, now=self.now + 3))
        self.db.chmod(0o600)
        before = self.db.read_bytes()
        self.assertEqual(store.validate_restored_pairing_master(
            self.db, master_key=self.master), 2)
        self.assertEqual(before, self.db.read_bytes())
        with self.assertRaises(store.PairingDenied):
            store.validate_restored_pairing_master(
                self.db, master_key=self.other_master)
        self.assertEqual(before, self.db.read_bytes())

    def test_offline_master_rejects_corruption_empty_or_missing_store(self):
        self.redeem(self.issue().code)
        self.db.chmod(0o600)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE smite_node_identities SET encrypted_secret='damaged'")
        with self.assertRaises(store.PairingDenied):
            store.validate_restored_pairing_master(
                self.db, master_key=self.master)
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM smite_node_identities")
        with self.assertRaises(store.PairingDenied):
            store.validate_restored_pairing_master(
                self.db, master_key=self.master)
        self.db.unlink()
        with self.assertRaises(store.PairingDenied):
            store.validate_restored_pairing_master(
                self.db, master_key=self.master)
        self.assertFalse(self.db.exists())

    def test_offline_master_rejects_unsafe_or_hot_database(self):
        self.redeem(self.issue().code)
        self.db.chmod(0o600)
        run = lambda: store.validate_restored_pairing_master(
            self.db, master_key=self.master)
        self.assertEqual(run(), 1)
        self.db.chmod(0o644)
        with self.assertRaises(store.PairingDenied):
            run()
        self.db.chmod(0o600)
        alias = Path(self.work.name) / "alias.db"
        alias.symlink_to(self.db)
        with self.assertRaises(store.PairingDenied):
            store.validate_restored_pairing_master(
                alias, master_key=self.master)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(self.db) + suffix)
            sidecar.write_bytes(b"unreviewed")
            with self.assertRaises(store.PairingDenied):
                run()
            sidecar.unlink()
        with sqlite3.connect(self.db) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
        with self.assertRaises(store.PairingDenied):
            run()

    def test_wrong_node_or_role_does_not_consume_code(self):
        approval = self.issue()
        with self.assertRaises(store.PairingDenied):
            self.redeem(approval.code, node_id=self.kh, role="foreign")
        with self.assertRaises(store.PairingDenied):
            self.redeem(approval.code, role="foreign")
        self.assertEqual(self.redeem(approval.code).node_id, self.ir)

    def test_expiry_is_enforced_at_boundary(self):
        approval = self.issue(ttl_seconds=60)
        with self.assertRaises(store.PairingDenied):
            self.redeem(approval.code, now=self.now + 60)
        with self.assertRaises(store.PairingDenied):
            self.redeem(approval.code, now=self.now + 601)
        # Expired redemption does not create a Node identity.
        with self.assertRaises(store.PairingDenied):
            store.get_active_secret(self.db, master_key=self.master, node_id=self.ir)

    def test_reissuance_invalidates_prior_unconsumed_code(self):
        first = self.issue()
        second = self.issue()
        self.assertNotEqual(first.code, second.code)
        with self.assertRaises(store.PairingDenied):
            self.redeem(first.code)
        self.assertEqual(self.redeem(second.code).node_id, self.ir)

    def test_concurrent_redeem_exactly_one_succeeds(self):
        approval = self.issue()

        def try_redeem(_):
            try:
                self.redeem(approval.code)
                return True
            except store.PairingDenied:
                return False

        with ThreadPoolExecutor(max_workers=16) as workers:
            outcomes = list(workers.map(try_redeem, range(32)))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 31)

    def test_reject_unknown_nodes_wrong_role_and_invalid_ttl(self):
        with self.assertRaises(store.PairingDenied):
            self.issue(node_id="nonexistent-node-99999")
        with self.assertRaises(store.PairingDenied):
            self.issue(role="foreign")
        for ttl in (0, 59, 901, 99999, True):
            with self.subTest(ttl=ttl), self.assertRaises(store.PairingDenied):
                self.issue(ttl_seconds=ttl)

    def test_reject_missing_master_and_bad_code_without_side_effect(self):
        with self.assertRaises(store.PairingDenied):
            store.issue_code(
                self.db, master_key=b"", node_id=self.ir,
                role="iran", admin_id="admin-12345678",
            )
        approval = self.issue()
        for code in ("", "smn1_fake", "smn1_" + "\u2603", approval.code + "tampered"):
            with self.subTest(code=code), self.assertRaises(store.PairingDenied):
                self.redeem(code)
        self.assertEqual(self.redeem(approval.code).node_id, self.ir)

    def test_node_role_changed_after_issuance_refuses_redeem(self):
        approval = self.issue()
        with sqlite3.connect(self.db) as conn:
            conn.execute(
                "UPDATE nodes SET metadata = ? WHERE id = ?",
                (json.dumps({"role": "foreign"}), self.ir),
            )
        with self.assertRaises(store.PairingDenied):
            self.redeem(approval.code)

    def test_revoke_is_effective_and_repair_cannot_repair_secret(self):
        approval = self.issue()
        self.redeem(approval.code)
        self.assertTrue(store.revoke_node(self.db, node_id=self.ir, now=self.now + 2))
        self.assertFalse(store.revoke_node(self.db, node_id=self.ir, now=self.now + 3))
        with self.assertRaises(store.PairingDenied):
            store.get_active_secret(self.db, master_key=self.master, node_id=self.ir)
        with self.assertRaises(store.PairingDenied):
            self.issue()


    def test_revocation_cancels_stale_codes_in_same_transaction(self):
        code = self.issue()
        credential = self.redeem(code.code)
        # Recreate an unsafe outstanding row in the isolated fixture, as
        # could occur after a partial old snapshot: revocation must consume it.
        with sqlite3.connect(self.db) as conn:
            conn.execute(
                "UPDATE smite_node_pairing_codes SET consumed_at=NULL "
                "WHERE node_id=?", (self.ir,)
            )
        self.assertTrue(store.revoke_node(self.db, node_id=self.ir, now=self.now + 7))
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM smite_node_pairing_codes "
                "WHERE node_id=? AND consumed_at IS NULL", (self.ir,)
            ).fetchone()[0], 0)
            self.assertEqual(conn.execute(
                "SELECT revoked_at FROM smite_node_identities WHERE node_id=?",
                (self.ir,),
            ).fetchone()[0], self.now + 7)
        with self.assertRaises(store.PairingDenied):
            self.redeem(code.code)
        with self.assertRaises(store.PairingDenied):
            store.get_active_secret(self.db, master_key=self.master, node_id=self.ir)
        self.assertNotIn(credential.secret.encode(), self.db.read_bytes())

    def test_revoke_missing_db_never_recreates_it(self):
        missing = Path(self.work.name) / "missing-panel.sqlite3"
        with self.assertRaises(store.PairingDenied):
            store.revoke_node(missing, node_id=self.ir)
        self.assertFalse(missing.exists())

    def test_operator_cli_requires_pause_backup_fresh_uuid_and_private_db(self):
        code = self.issue()
        old = self.redeem(code.code).secret
        self.db.chmod(0o600)
        cmd = [sys.executable, "-B", str(PATH),
               "--database", str(self.db), "--node-id", self.ir]
        no_permission = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        self.assertEqual(no_permission.returncode, 2)
        self.assertFalse(store.revoke_node(
            self.db, node_id="not-enrolled-node", now=self.now + 1
        ))
        approved = cmd + [
            "--confirm-signed-panel-and-node-paused",
            "--confirm-reviewed-panel-db-backup",
            "--confirm-replacement-uses-new-node-id",
        ]
        first = subprocess.run(
            approved, capture_output=True, text=True, timeout=10
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("SAME_NODE_ID_REKEY=FORBIDDEN", first.stdout)
        self.assertIn("NODE_AGENT_STILL_REQUIRES_OFFLINE_PAUSE_AND_KEY_RETIREMENT=YES", first.stdout)
        self.assertIn("RELEASE_OR_ACTIVATION_AUTHORIZED=NO", first.stdout)
        self.assertNotIn(old, first.stdout + first.stderr)
        with self.assertRaises(store.PairingDenied):
            store.get_active_secret(self.db, master_key=self.master, node_id=self.ir)
        second = subprocess.run(
            approved, capture_output=True, text=True, timeout=10
        )
        self.assertEqual(second.returncode, 2)
        self.assertIn("HOLD", second.stderr)

    def test_cli_rejects_world_readable_or_symlinked_panel_db(self):
        self.redeem(self.issue().code)
        approved = [sys.executable, "-B", str(PATH),
                    "--database", str(self.db), "--node-id", self.ir,
                    "--confirm-signed-panel-and-node-paused",
                    "--confirm-reviewed-panel-db-backup",
                    "--confirm-replacement-uses-new-node-id"]
        unsafe = subprocess.run(approved, capture_output=True, text=True, timeout=10)
        self.assertEqual(unsafe.returncode, 2)
        alias = Path(self.work.name) / "alias.db"
        alias.symlink_to(self.db)
        self.db.chmod(0o600)
        cmd = approved.copy()
        cmd[cmd.index(str(self.db))] = str(alias)
        symlink = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        self.assertEqual(symlink.returncode, 2)
        self.assertEqual(store.get_active_secret(
            self.db, master_key=self.master, node_id=self.ir
        ).__len__(), 64)

    def test_schema_reentrant_and_no_wiring_to_live_endpoints(self):
        store.initialize_schema(self.db)
        # Service remains inert until authenticated endpoint adapter,
        # verified TLS client and U-OPTI pairing wizard are implemented.
        self.assertNotIn("node_pairing_store", (ROOT / "panel/main.py").read_text())
        self.assertNotIn("node_pairing_store", (ROOT / "panel/app/routers/nodes.py").read_text())
        self.assertNotIn("node_pairing_store", (ROOT / "node/app/panel_client.py").read_text())


if __name__ == "__main__":
    unittest.main()
