"""Managed FRP readiness requires BOTH role binaries and exact SHA-256.

Only synthetic, executable-looking bytes in a disposable temp directory.
No tunnel, Docker, network, or production host access is performed.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "node"))
from app.config import settings
from app import engine_inventory as inventory


class ManagedFrpPair(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="smite-managed-frp-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        state = self.root / "engine-state"
        state.mkdir(mode=0o700)
        self.manifest = state / "engines.json"
        self.client = self.root / "frpc"
        self.server = self.root / "frps"
        self.client.write_bytes(b"\x7fELF-frpc-test-contents")
        self.server.write_bytes(b"\x7fELF-frps-test-contents")
        self.client.chmod(0o755)
        self.server.chmod(0o755)
        self.sha_client = hashlib.sha256(self.client.read_bytes()).hexdigest()
        self.sha_server = hashlib.sha256(self.server.read_bytes()).hexdigest()
        old_mode = settings.smite_engine_inventory_mode
        old_path = settings.smite_engine_manifest_path
        settings.smite_engine_inventory_mode = "managed"
        settings.smite_engine_manifest_path = str(self.manifest)
        def restore():
            settings.smite_engine_inventory_mode = old_mode
            settings.smite_engine_manifest_path = old_path
        self.addCleanup(restore)
        actual = inventory.binary_path_for_engine

        def route(name):
            if name == "frp":
                return self.client
            return actual(name)
        patcher = patch.object(inventory, "binary_path_for_engine", side_effect=route)
        patcher.start()
        self.addCleanup(patcher.stop)
        real_path = inventory.Path

        # Replace the fixed server binary locator exclusively for this
        # unit test. Both Paths continue to be ordinary temp files.
        def fake_path(arg):
            if arg == "/usr/local/bin/frps":
                return self.server
            return real_path(arg)
        server_patcher = patch.object(inventory, "Path", side_effect=fake_path)
        server_patcher.start()
        self.addCleanup(server_patcher.stop)

    def record(self, item):
        self.manifest.write_text(json.dumps({"schema": 1, "engines": {"frp": item}}))
        self.manifest.chmod(0o600)

    def status(self):
        return inventory.engine_inventory()["engines"]["frp"]

    def test_both_pinned_binaries_become_ready_without_backhaul(self):
        self.record({"sha256": self.sha_client, "server_sha256": self.sha_server})
        self.assertEqual(self.status(), "ready")
        self.assertEqual(inventory.engine_inventory()["engines"]["backhaul"], "not-installed")

    def test_frpc_only_legacy_record_fails_closed(self):
        self.record({"sha256": self.sha_client})
        self.assertEqual(self.status(), "unavailable")
        with self.assertRaises(inventory.EngineInventoryUnavailable):
            inventory.require_engine_ready("frp")

    def test_server_missing_changed_or_bad_permissions_fails_closed(self):
        self.record({"sha256": self.sha_client, "server_sha256": self.sha_server})
        self.server.write_bytes(b"\x7fELF-wrong")
        self.assertEqual(self.status(), "unavailable")
        self.server.write_bytes(b"\x7fELF-frps-test-contents")
        self.server.chmod(0o777)
        self.assertEqual(self.status(), "unavailable")
        self.server.chmod(0o755)
        self.assertEqual(self.status(), "ready")
        self.server.unlink()
        self.assertEqual(self.status(), "unavailable")

    def test_client_corrupt_and_server_digest_malformed_rejected(self):
        self.record({"sha256": self.sha_client, "server_sha256": "X" * 64})
        with self.assertRaises(inventory.EngineInventoryUnavailable):
            self.status()
        self.record({"sha256": self.sha_client, "server_sha256": self.sha_server})
        self.client.write_bytes(b"\x7fELF-bad")
        self.assertEqual(self.status(), "unavailable")

    def test_frp_unrecognized_fields_are_not_silently_accepted(self):
        self.record({"sha256": self.sha_client, "server_sha256": self.sha_server,
                     "extra": "untrusted"})
        with self.assertRaises(inventory.EngineInventoryUnavailable):
            self.status()


if __name__ == "__main__":
    unittest.main(verbosity=2)
