"""Restart must not bypass managed engine enrollment and SHA verification.

Offline-only: never runs a real tunnel engine, Docker or network API.
"""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "node"))

from app.config import settings
from app.engine_inventory import EngineInventoryUnavailable
from app.core_adapters import AdapterManager


class ManagedRestartTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.old_mode = settings.smite_engine_inventory_mode
        settings.smite_engine_inventory_mode = "managed"
        self.addAsyncCleanup(self.restore_mode)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.manager = object.__new__(AdapterManager)
        self.manager.config_dir = Path(self.tmp.name)
        self.manager.tunnels_file = self.manager.config_dir / "tunnels.json"
        self.manager.tunnel_configs = {
            "saved-tunnel": {"core": "backhaul", "spec": {"mode": "client"}}
        }
        self.manager.active_tunnels = {}
        self.adapter = Mock()
        self.adapter.name = "backhaul"
        self.manager.get_adapter = Mock(return_value=self.adapter)
        self.manager._load_tunnels = Mock()
        self.manager._save_tunnels = Mock()

    async def restore_mode(self):
        settings.smite_engine_inventory_mode = self.old_mode

    async def test_invalid_enrollment_cannot_autostart_stored_tunnel(self):
        with patch("app.engine_inventory.require_engine_ready",
                   side_effect=EngineInventoryUnavailable("not ready")) as gate:
            await self.manager.restore_tunnels()
        gate.assert_called_once_with("backhaul")
        self.adapter.apply.assert_not_called()
        self.manager.get_adapter.assert_not_called()
        self.assertEqual(self.manager.active_tunnels, {})
        # Persisted configuration is not deleted: operator can repair engine.
        self.assertIn("saved-tunnel", self.manager.tunnel_configs)

    async def test_ready_enrollment_restores_one_saved_tunnel(self):
        with patch("app.engine_inventory.require_engine_ready") as gate:
            await self.manager.restore_tunnels()
        gate.assert_called_once_with("backhaul")
        self.adapter.apply.assert_called_once_with("saved-tunnel", {"mode": "client"})
        self.assertIn("saved-tunnel", self.manager.active_tunnels)

    async def test_direct_adapter_apply_denies_before_existing_removal(self):
        self.manager.active_tunnels = {"saved-tunnel": self.adapter}
        self.manager.remove_tunnel = Mock()
        with patch("app.engine_inventory.require_engine_ready",
                   side_effect=EngineInventoryUnavailable("no binary")) as gate:
            with self.assertRaises(EngineInventoryUnavailable):
                await self.manager.apply_tunnel(
                    "saved-tunnel", "backhaul", {"mode": "client"})
        gate.assert_called_once_with("backhaul")
        self.manager.remove_tunnel.assert_not_called()
        self.adapter.remove.assert_not_called()
        self.adapter.apply.assert_not_called()

    async def test_graceful_shutdown_preserves_frp_persistence_for_next_boot(self):
        """Regression: RC3 shutdown erased KH FRPC tunnels.json on recreate."""
        import json
        from hashlib import sha256

        record = {
            "core": "frp",
            "spec": {"mode": "client", "local_port": 45121, "remote_port": 45121},
        }
        self.manager.tunnel_configs = {"trial-frp-45121": record}
        self.manager.active_tunnels = {"trial-frp-45121": self.adapter}
        self.manager._save_tunnels = AdapterManager._save_tunnels.__get__(self.manager)
        self.manager._save_tunnels()
        before = self.manager.tunnels_file.read_bytes()
        before_hash = sha256(before).hexdigest()

        await self.manager.cleanup()

        self.adapter.remove.assert_called_once_with("trial-frp-45121")
        self.assertEqual(self.manager.active_tunnels, {})
        self.assertEqual(self.manager.tunnel_configs, {"trial-frp-45121": record})
        self.assertEqual(sha256(self.manager.tunnels_file.read_bytes()).hexdigest(), before_hash)
        self.assertEqual(json.loads(self.manager.tunnels_file.read_text()),
                         {"trial-frp-45121": record})

        # Simulate a fresh Node process: reload exactly the same mounted volume.
        cold_boot = object.__new__(AdapterManager)
        cold_boot.config_dir = self.manager.config_dir
        cold_boot.tunnels_file = self.manager.tunnels_file
        cold_boot.tunnel_configs = {}
        cold_boot.active_tunnels = {}
        cold_boot.get_adapter = Mock(return_value=self.adapter)
        self.adapter.reset_mock()
        with patch("app.engine_inventory.require_engine_ready") as enrolled:
            await cold_boot.restore_tunnels()
        enrolled.assert_called_once_with("frp")
        self.adapter.apply.assert_called_once_with(
            "trial-frp-45121", record["spec"])
        self.assertIn("trial-frp-45121", cold_boot.active_tunnels)

    async def test_failed_shutdown_stop_cannot_erase_saved_specs(self):
        import json
        record = {"core": "frp", "spec": {"mode": "client"}}
        self.manager.tunnel_configs = {"saved": record}
        self.manager.active_tunnels = {"saved": self.adapter}
        self.manager._save_tunnels = AdapterManager._save_tunnels.__get__(self.manager)
        self.manager._save_tunnels()
        before = self.manager.tunnels_file.read_bytes()
        self.adapter.remove.side_effect = RuntimeError("redact-secret-material")

        await self.manager.cleanup()

        self.assertEqual(self.manager.tunnels_file.read_bytes(), before)
        self.assertEqual(self.manager.tunnel_configs, {"saved": record})
        self.assertIn("saved", self.manager.active_tunnels)
        self.assertEqual(json.loads(self.manager.tunnels_file.read_text()),
                         {"saved": record})

    async def test_explicit_remove_still_deletes_saved_tunnel(self):
        import json
        record = {"core": "frp", "spec": {"mode": "client"}}
        self.manager.tunnel_configs = {"saved": record}
        self.manager.active_tunnels = {"saved": self.adapter}
        self.manager._save_tunnels = AdapterManager._save_tunnels.__get__(self.manager)
        self.manager._save_tunnels()

        await self.manager.remove_tunnel("saved")

        self.adapter.remove.assert_called_once_with("saved")
        self.assertEqual(json.loads(self.manager.tunnels_file.read_text()), {})
        self.assertEqual(self.manager.tunnel_configs, {})
        self.assertEqual(self.manager.active_tunnels, {})

    async def test_legacy_restore_keeps_stable_behavior(self):
        settings.smite_engine_inventory_mode = "legacy"
        with patch("app.engine_inventory.require_engine_ready",
                   side_effect=AssertionError("legacy unexpectedly gated")) as gate:
            await self.manager.restore_tunnels()
        gate.assert_not_called()
        self.adapter.apply.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
