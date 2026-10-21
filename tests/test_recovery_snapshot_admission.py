"""Offline Panel restore anti-rollback witness; no real Node or services."""
from pathlib import Path
import hashlib
import importlib.util
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "panel/app/recovery_snapshot_admission.py"
spec = importlib.util.spec_from_file_location("smite_recovery_snapshot_test", path)
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)

storepath = ROOT / "panel/app/node_pairing_store.py"
spec2 = importlib.util.spec_from_file_location("smite_pairing_restored_test", storepath)
store = importlib.util.module_from_spec(spec2)
sys.modules[spec2.name] = store
spec2.loader.exec_module(store)


class RestoreWitnessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dbdir, self.wdir = self.root/"panel", self.root/"independent-witness"
        self.dbdir.mkdir(mode=0o700)
        self.wdir.mkdir(mode=0o700)
        self.db, self.witness = self.dbdir/"panel.db", self.wdir/"old-node.json"
        self.node = "bbbbbbbb-1111-2222-3333-444444444444"
        self.master = Fernet.generate_key()
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE nodes (id TEXT PRIMARY KEY, metadata TEXT)")
            conn.execute("INSERT INTO nodes VALUES (?, ?)",
                         (self.node, json.dumps({"role":"foreign"})))
        self.db.chmod(0o600)
        store.initialize_schema(self.db)
        code = store.issue_code(self.db,master_key=self.master,node_id=self.node,
                                role="foreign",admin_id="operator",now=1850000000)
        store.redeem_code(self.db,master_key=self.master,node_id=self.node,
                          role="foreign",code=code.code,now=1850000001)
        self.before = self.root/"before-panel-revoke.db"
        shutil.copy2(self.db,self.before)
        self.assertTrue(store.revoke_node(self.db,node_id=self.node,now=1850000050))
        self.hash = admission.create_witness(
            database=self.db,node_id=self.node,output=self.witness)

    def verified(self, **changes):
        kw = {"database":self.db,"node_id":self.node,
              "witness":self.witness,"witness_sha256":self.hash}
        kw.update(changes)
        admission.verify_witness(**kw)

    def test_current_revocation_passes_without_activating(self):
        self.verified()
        doc = json.loads(self.witness.read_bytes())
        self.assertEqual(doc["revoked_at"],1850000050)
        self.assertFalse(doc["activation_allowed"])
        self.assertFalse(doc["snapshot_restore_approved"])
        self.assertNotIn("secret",self.witness.read_text())

    def test_old_panel_snapshot_revives_key_but_gate_holds(self):
        self.verified()
        self.db.unlink()
        shutil.copy2(self.before,self.db)
        self.assertEqual(len(store.get_active_secret(
            self.db,master_key=self.master,node_id=self.node)),64)
        with self.assertRaisesRegex(admission.RecoveryHold,"Old Node key active"):
            self.verified()
        # The gate is read-only: never silently revoke/repair restored data.
        self.assertEqual(len(store.get_active_secret(
            self.db,master_key=self.master,node_id=self.node)),64)

    def test_replaced_witness_wrong_trust_sha_and_symlink_hold(self):
        with self.assertRaises(admission.RecoveryHold):
            self.verified(witness_sha256="f"*64)
        self.witness.write_text("{}")
        with self.assertRaises(admission.RecoveryHold):
            self.verified()
        self.witness.unlink()
        self.witness.symlink_to(self.before)
        with self.assertRaises(admission.RecoveryHold):
            self.verified()

    def test_missing_panel_db_never_recreates_with_any_pairing_operation(self):
        missing=self.dbdir/"not-there.db"
        with self.assertRaises(store.PairingDenied):
            store.get_active_secret(missing,master_key=self.master,node_id=self.node)
        with self.assertRaises(store.PairingDenied):
            store.issue_code(missing,master_key=self.master,node_id=self.node,
                             role="foreign",admin_id="operator",now=1850000100)
        with self.assertRaises(store.PairingDenied):
            store.initialize_schema(missing)
        with self.assertRaises(admission.RecoveryHold):
            self.verified(database=missing)
        self.assertFalse(missing.exists())

    def test_no_witness_creation_for_active_node_or_existing_file(self):
        other=self.wdir/"different-witness.json"
        self.db.unlink()
        shutil.copy2(self.before,self.db)
        with self.assertRaises(admission.RecoveryHold):
            admission.create_witness(database=self.db,node_id=self.node,output=other)
        self.assertFalse(other.exists())
        self.assertTrue(self.witness.exists())

    def test_private_permissions_and_path_separation(self):
        self.witness.chmod(0o644)
        with self.assertRaises(admission.RecoveryHold):
            self.verified()
        self.witness.chmod(0o600)
        self.db.chmod(0o644)
        with self.assertRaises(admission.RecoveryHold):
            self.verified()
        self.db.chmod(0o600)
        with self.assertRaises(admission.RecoveryHold):
            admission.create_witness(
                database=self.db,node_id=self.node,output=self.dbdir/"bad.json")

if __name__ == "__main__":
    unittest.main(verbosity=2)
