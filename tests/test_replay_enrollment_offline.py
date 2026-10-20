"""Offline one-time Node Replay DB enrollment regression and negative tests.

No secrets in log, network, ports, container mounts, real VPS or lifecycle
changes. Real Smite identity reader and durable SQLite initializer execute
against private temporary paths.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "node"))
from app.agent_auth import AgentAuthUnavailable, DurableNonceStore
from app.replay_enrollment import ReplayEnrollmentHold, provision_once


class OfflineFirstEnrollmentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="smite-replay-enrollment-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.identity_dir = root / "paired-identity"
        self.replay_dir = root / "persistent-replay"
        self.identity_dir.mkdir(mode=0o700)
        self.replay_dir.mkdir(mode=0o700)
        self.identity = self.identity_dir / "node-identity.json"
        self.db = self.replay_dir / "agent-replay.sqlite3"
        self.marker = self.identity_dir / "replay-enrollment.json"
        self.node_id = "bbbbbbbb-1111-2222-3333-444444444444"
        self.secret = "c" * 64
        self.identity.write_text(json.dumps({
            "version": 1, "node_id": self.node_id, "node_secret": self.secret
        }))
        self.identity.chmod(0o600)

    def enroll(self):
        provision_once(identity_path=self.identity, replay_path=self.db)

    def test_first_enrollment_creates_private_bound_store_and_marker(self):
        self.enroll()
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        ledger = json.loads(self.marker.read_text())
        self.assertEqual(ledger["node_id"], self.node_id)
        self.assertEqual(ledger["replay_database"], str(self.db))
        self.assertEqual(ledger["status"], "ENROLLMENT_STARTED")
        self.assertNotIn(self.secret, self.marker.read_text())
        with closing(sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)) as con:
            self.assertEqual(con.execute("PRAGMA user_version").fetchone(), (1,))
            self.assertEqual(con.execute("SELECT node_id FROM replay_store_identity").fetchall(),
                             [(self.node_id,)])
        store = DurableNonceStore(self.db)
        nonce = "a" * 32
        self.assertTrue(store.register(self.node_id, nonce, int(time.time())))
        self.assertFalse(DurableNonceStore(self.db).register(
            self.node_id, nonce, int(time.time())))
        with self.assertRaisesRegex(ReplayEnrollmentHold, "already started"):
            self.enroll()
        self.assertFalse(DurableNonceStore(self.db).register(
            self.node_id, nonce, int(time.time())))

    def test_loss_of_database_does_not_turn_second_call_into_first_boot(self):
        self.enroll()
        self.db.unlink()
        self.assertFalse(self.db.exists())
        with self.assertRaisesRegex(ReplayEnrollmentHold, "already started"):
            self.enroll()
        self.assertFalse(self.db.exists())
        self.assertTrue(self.marker.is_file())

    def test_partial_initialization_leaves_durable_marker_and_no_retry(self):
        with patch("app.replay_enrollment.DurableNonceStore.initialize_new",
                   side_effect=AgentAuthUnavailable("simulated disk full")):
            with self.assertRaisesRegex(ReplayEnrollmentHold, "quarantine"):
                self.enroll()
        self.assertTrue(self.marker.is_file())
        self.assertFalse(self.db.exists())
        with self.assertRaisesRegex(ReplayEnrollmentHold, "already started"):
            self.enroll()
        self.assertFalse(self.db.exists())

    def test_existing_or_damaged_db_blocks_fresh_bootstrap(self):
        self.db.write_bytes(b"unknown previous state")
        self.db.chmod(0o600)
        with self.assertRaisesRegex(ReplayEnrollmentHold, "already exists"):
            self.enroll()
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.db.read_bytes(), b"unknown previous state")

    def test_rejects_unsafe_identity_replay_and_marker_symlinks(self):
        self.identity.chmod(0o644)
        with self.assertRaises(ReplayEnrollmentHold):
            self.enroll()
        self.identity.chmod(0o600)
        self.replay_dir.chmod(0o755)
        with self.assertRaises(ReplayEnrollmentHold):
            self.enroll()
        self.replay_dir.chmod(0o700)
        self.marker.symlink_to(self.identity)
        with self.assertRaisesRegex(ReplayEnrollmentHold, "already started"):
            self.enroll()
        self.marker.unlink()
        self.db.symlink_to(self.identity)
        with self.assertRaisesRegex(ReplayEnrollmentHold, "already exists"):
            self.enroll()
        self.assertFalse(self.marker.exists())

    def test_failed_identity_validation_never_consumes_marker(self):
        self.identity.write_text("not json")
        with self.assertRaisesRegex(ReplayEnrollmentHold, "Valid, previously paired"):
            self.enroll()
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.db.exists())

    def test_replay_and_identity_same_parent_refused(self):
        with self.assertRaisesRegex(ReplayEnrollmentHold, "separate private"):
            provision_once(identity_path=self.identity,
                           replay_path=self.identity_dir/"replay.sqlite3")
        self.assertFalse(self.marker.exists())

    def test_cli_requires_explicit_opt_in_and_never_prints_secrets(self):
        cmd = [sys.executable, "-B", "-m", "app.replay_enrollment",
               "--identity", str(self.identity),
               "--replay-db", str(self.db)]
        env = {**os.environ, "PYTHONPATH": str(ROOT / "node")}
        unconfirmed = subprocess.run(cmd, env=env, capture_output=True,
                                     text=True, timeout=10)
        self.assertEqual(unconfirmed.returncode, 2)
        self.assertFalse(self.db.exists())
        confirmed = subprocess.run(cmd + ["--confirm-first-provision"],
                                   env=env, capture_output=True,
                                   text=True, timeout=10)
        self.assertEqual(confirmed.returncode, 0, confirmed.stderr)
        self.assertIn("SIGNED_TRAFFIC_ACTIVATION=NOT_AUTHORIZED", confirmed.stdout)
        self.assertNotIn(self.secret, confirmed.stdout + confirmed.stderr)
        retried = subprocess.run(cmd + ["--confirm-first-provision"],
                                 env=env, capture_output=True,
                                 text=True, timeout=10)
        self.assertEqual(retried.returncode, 2)
        self.assertNotIn(self.secret, retried.stdout + retried.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
