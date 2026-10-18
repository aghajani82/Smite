"""Offline integration tests for atomic, single-use Node pairing persistence.

Uses temporary SQLite only. No Smite services, HTTP endpoints, tunnel
commands, GitHub deployment, or VPS access.
"""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
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

    def test_schema_reentrant_and_no_wiring_to_live_endpoints(self):
        store.initialize_schema(self.db)
        # Service remains inert until authenticated endpoint adapter,
        # verified TLS client and U-OPTI pairing wizard are implemented.
        self.assertNotIn("node_pairing_store", (ROOT / "panel/main.py").read_text())
        self.assertNotIn("node_pairing_store", (ROOT / "panel/app/routers/nodes.py").read_text())
        self.assertNotIn("node_pairing_store", (ROOT / "node/app/panel_client.py").read_text())


if __name__ == "__main__":
    unittest.main()
