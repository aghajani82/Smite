"""Disposable stale-replay snapshot and one-way quarantine regression.

Includes the real Smite signer/verifier and actual SQLite. No production
restore, network, runtime-mode change, key logging or automatic unlock.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"node"))

from app.agent_auth import (
    AgentAuthUnavailable, RESTORE_HOLD_NAME, verify_agent_envelope
)
from app.node_auth import MAX_CLOCK_SKEW, sign_request
from app.replay_enrollment import provision_once
from app.replay_restore_hold import quarantine


class StaleSnapshotQuarantineTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="smite-stale-replay-offline-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.identity_dir = root/"identities"
        self.replay_dir = root/"replay"
        for folder in (self.identity_dir, self.replay_dir):
            folder.mkdir(mode=0o700)
        self.identity = self.identity_dir/"node-identity.json"
        self.replay = self.replay_dir/"agent-replay.sqlite3"
        self.hold = self.identity_dir/RESTORE_HOLD_NAME
        self.node_id = "bbbbbbbb-1111-2222-3333-444444444444"
        self.secret = "a"*64
        self.identity.write_text(json.dumps({
            "version": 1, "node_id": self.node_id,
            "node_secret": self.secret
        }))
        self.identity.chmod(0o600)
        provision_once(identity_path=self.identity, replay_path=self.replay)

    def envelope(self, nonce: str):
        headers = sign_request(secret=self.secret, node_id=self.node_id,
                               method="GET", target="/api/agent/status",
                               nonce=nonce, body=b"", timestamp=int(time.time()))
        return dict(identity_path=str(self.identity), replay_path=str(self.replay),
                    method="GET", target="/api/agent/status", body=b"",
                    headers=headers)

    def test_quarantined_old_snapshot_never_reaccepts_signed_nonce(self):
        historical = self.replay_dir/"snapshot-before-nonce.sqlite3"
        shutil.copy2(self.replay, historical)
        signed = self.envelope("b"*32)
        self.assertTrue(verify_agent_envelope(**signed))
        # Operator MUST stop signing and stop the node before running this
        # separate one-way quarantine command; fixture models that order.
        quarantine(identity_path=self.identity, replay_path=self.replay)
        self.assertEqual(self.hold.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.secret, self.hold.read_text())
        os.replace(historical, self.replay)  # deliberate stale same-id rollback
        self.assertTrue(self.replay.exists())
        with self.assertRaisesRegex(AgentAuthUnavailable, "quarantined"):
            verify_agent_envelope(**signed)
        with self.assertRaisesRegex(AgentAuthUnavailable, "quarantined"):
            verify_agent_envelope(**self.envelope("c"*32))
        with self.assertRaisesRegex(AgentAuthUnavailable, "quarantined"):
            verify_agent_envelope(**self.envelope("d"*32))
        self.assertTrue(self.hold.exists())  # no automatic drain/release
        with self.assertRaises(Exception):
            quarantine(identity_path=self.identity, replay_path=self.replay)
        self.assertTrue(self.hold.exists())

    def test_untrusted_marker_is_hold_not_legacy_fallback(self):
        quarantine(identity_path=self.identity, replay_path=self.replay)
        for invalid in (
            '{"schema":1,"node_id":"wrong","status":"QUARANTINED","replay_database":"x"}',
            "broken-json",
            '{"schema":1,"node_id":"%s","status":"UNLOCKED","replay_database":"x"}'
            % self.node_id
        ):
            self.hold.write_text(invalid)
            with self.assertRaises(AgentAuthUnavailable):
                verify_agent_envelope(**self.envelope("d"*32))
        self.hold.chmod(0o644)
        with self.assertRaises(AgentAuthUnavailable):
            verify_agent_envelope(**self.envelope("e"*32))
        self.hold.unlink()
        self.hold.symlink_to(self.identity)
        with self.assertRaises(AgentAuthUnavailable):
            verify_agent_envelope(**self.envelope("f"*32))

    def test_bad_existing_enrollment_prevents_quarantine_setup(self):
        (self.identity_dir/"replay-enrollment.json").unlink()
        with self.assertRaises(Exception):
            quarantine(identity_path=self.identity, replay_path=self.replay)
        self.assertFalse(self.hold.exists())

    def test_cli_does_not_auto_unlock_or_print_secrets(self):
        cmd = [sys.executable, "-B", "-m", "app.replay_restore_hold",
               "--identity", str(self.identity),
               "--replay-db", str(self.replay)]
        env = {**os.environ, "PYTHONPATH": str(ROOT/"node")}
        missing = subprocess.run(cmd, env=env, capture_output=True,
                                 text=True, timeout=12)
        self.assertEqual(missing.returncode, 2)
        self.assertFalse(self.hold.exists())
        done = subprocess.run(cmd+["--confirm-offline-quarantine"], env=env,
                              capture_output=True, text=True, timeout=12)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("AUTOMATIC_RELEASE=NEVER", done.stdout)
        self.assertNotIn(self.secret, done.stdout + done.stderr)
        again = subprocess.run(cmd+["--confirm-offline-quarantine"], env=env,
                               capture_output=True, text=True, timeout=12)
        self.assertEqual(again.returncode, 2)
        self.assertTrue(self.hold.exists())
        self.assertEqual(MAX_CLOCK_SKEW, 90)
        # The 90s window is a code-derived reference, NOT an auto-unlock.
        self.assertFalse(any("unlock" in field for field in
                             json.loads(self.hold.read_text())))


if __name__ == "__main__":
    unittest.main(verbosity=2)
