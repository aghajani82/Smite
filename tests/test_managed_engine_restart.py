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
from app.uopti_backhaul_standard import StandardBackhaulSpecError

SAFE_SPEC = {
    "uopti_standard_backhaul": True,
    "mode": "client",
    "token": "TEST-SAFE-ONLY-TOKEN-0123456789ABCDEF",
    "transport": "ws",
    "type": "ws",
    "ports": ["127.0.0.1:56053=127.0.0.1:56053"],
    "data_port": 56053,
    "control_port": 3080,
    "bridge_port": 13080,
    "remote_addr": "127.0.0.1:13080",
}


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

    async def test_ready_enrollment_does_not_autostart_unapproved_saved_tunnel(self):
        # Both hosts being READY must not revive legacy public listeners.
        with patch("app.engine_inventory.require_engine_ready") as gate:
            await self.manager.restore_tunnels()
        gate.assert_called_once_with("backhaul")
        self.adapter.apply.assert_not_called()
        self.manager.get_adapter.assert_not_called()
        self.assertEqual(self.manager.active_tunnels, {})
        self.assertIn("saved-tunnel", self.manager.tunnel_configs)

    async def test_ready_enrollment_restores_approved_loopback_tunnel(self):
        from app.uopti_backhaul_standard import normalize_node_spec
        self.manager.tunnel_configs["saved-tunnel"]["spec"] = SAFE_SPEC.copy()
        with patch("app.engine_inventory.require_engine_ready") as gate:
            await self.manager.restore_tunnels()
        gate.assert_called_once_with("backhaul")
        self.adapter.apply.assert_called_once_with(
            "saved-tunnel", normalize_node_spec(SAFE_SPEC))
        self.assertIn("saved-tunnel", self.manager.active_tunnels)

    async def test_ready_engine_rejects_unapproved_direct_apply_before_removal(self):
        self.manager.active_tunnels = {"saved-tunnel": self.adapter}
        self.manager.remove_tunnel = Mock()
        with patch("app.engine_inventory.require_engine_ready") as gate:
            with self.assertRaises(StandardBackhaulSpecError):
                await self.manager.apply_tunnel(
                    "saved-tunnel", "backhaul", {"mode": "server", "bind_addr": "0.0.0.0:3080"})
        gate.assert_called_once_with("backhaul")
        self.manager.remove_tunnel.assert_not_called()
        self.adapter.apply.assert_not_called()

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

    async def test_direct_backhaul_adapter_rejects_unsafe_without_stopping_process(self):
        from app.core_adapters import BackhaulAdapter
        adapter = object.__new__(BackhaulAdapter)
        adapter.config_dir = self.manager.config_dir
        running = Mock()
        adapter.processes = {"saved-tunnel": running}
        adapter.log_handles = {}
        with self.assertRaises(StandardBackhaulSpecError):
            adapter.apply(
                "saved-tunnel", {"mode": "server", "bind_addr": "0.0.0.0:3080"},
            )
        running.terminate.assert_not_called()
        running.kill.assert_not_called()
        self.assertFalse((self.manager.config_dir / "saved-tunnel.toml").exists())

    async def test_managed_backhaul_duplicate_signed_apply_keeps_live_process(self):
        # Replaying an identical, approved signed request must never cause
        # even a transient interruption or a rewrite of persisted secrets.
        from unittest.mock import AsyncMock
        self.manager.tunnel_configs["saved-tunnel"] = {
            "core": "backhaul", "spec": SAFE_SPEC.copy()}
        self.manager.active_tunnels = {"saved-tunnel": self.adapter}
        self.adapter.status.return_value = {"active": True}
        self.manager.remove_tunnel = AsyncMock()
        original = self.manager.tunnel_configs["saved-tunnel"].copy()
        with patch("app.engine_inventory.require_engine_ready") as verified:
            await self.manager.apply_tunnel("saved-tunnel", "backhaul",
                                            SAFE_SPEC.copy())
        verified.assert_called_once_with("backhaul")
        self.manager.remove_tunnel.assert_not_awaited()
        self.manager.get_adapter.assert_not_called()
        self.adapter.apply.assert_not_called()
        self.adapter.remove.assert_not_called()
        self.manager._save_tunnels.assert_not_called()
        self.assertEqual(self.manager.tunnel_configs["saved-tunnel"], original)
        self.assertIs(self.manager.active_tunnels["saved-tunnel"], self.adapter)

    async def test_managed_backhaul_changed_signed_apply_refuses_before_stop(self):
        from unittest.mock import AsyncMock
        self.manager.tunnel_configs["saved-tunnel"] = {
            "core": "backhaul", "spec": SAFE_SPEC.copy()}
        self.manager.active_tunnels = {"saved-tunnel": self.adapter}
        self.adapter.status.return_value = {"active": True}
        self.manager.remove_tunnel = AsyncMock()
        changed = dict(SAFE_SPEC, token="ANOTHER-VALID-TEST-TOKEN-00000000123456789")
        with patch("app.engine_inventory.require_engine_ready") as verified:
            with self.assertRaisesRegex(RuntimeError, "explicit removal"):
                await self.manager.apply_tunnel("saved-tunnel", "backhaul", changed)
        verified.assert_called_once_with("backhaul")
        self.manager.remove_tunnel.assert_not_awaited()
        self.adapter.remove.assert_not_called()
        self.adapter.apply.assert_not_called()
        self.manager._save_tunnels.assert_not_called()
        self.assertEqual(self.manager.tunnel_configs["saved-tunnel"]["spec"], SAFE_SPEC)

    async def test_managed_backhaul_mismatched_id_cannot_delete_existing_frp(self):
        from unittest.mock import AsyncMock
        self.manager.tunnel_configs["saved-tunnel"] = {
            "core": "frp", "spec": {"mode": "client"}}
        self.manager.active_tunnels = {"saved-tunnel": self.adapter}
        self.adapter.name = "frp"
        self.manager.remove_tunnel = AsyncMock()
        with patch("app.engine_inventory.require_engine_ready") as verified:
            with self.assertRaisesRegex(RuntimeError, "explicit removal"):
                await self.manager.apply_tunnel("saved-tunnel", "backhaul",
                                                SAFE_SPEC.copy())
        verified.assert_called_once_with("backhaul")
        self.manager.remove_tunnel.assert_not_awaited()
        self.adapter.apply.assert_not_called()
        self.adapter.remove.assert_not_called()
        self.manager._save_tunnels.assert_not_called()
        self.assertEqual(self.manager.tunnel_configs["saved-tunnel"]["core"], "frp")

    async def test_managed_backhaul_unverified_active_state_cannot_reapply(self):
        from unittest.mock import AsyncMock
        self.manager.tunnel_configs["saved-tunnel"] = {
            "core": "backhaul", "spec": SAFE_SPEC.copy()}
        self.manager.active_tunnels = {"saved-tunnel": self.adapter}
        self.manager.remove_tunnel = AsyncMock()
        self.adapter.status.return_value = {"active": False}
        with patch("app.engine_inventory.require_engine_ready") as verified:
            with self.assertRaisesRegex(RuntimeError, "explicit removal"):
                await self.manager.apply_tunnel("saved-tunnel", "backhaul",
                                                SAFE_SPEC.copy())
        verified.assert_called_once_with("backhaul")
        self.manager.remove_tunnel.assert_not_awaited()
        self.adapter.remove.assert_not_called()
        self.manager._save_tunnels.assert_not_called()

    async def test_direct_managed_backhaul_reapply_cannot_stop_running_process(self):
        # Defense in depth: direct Adapter callers must not bypass Manager.
        from app.core_adapters import BackhaulAdapter
        adapter = object.__new__(BackhaulAdapter)
        adapter.config_dir = self.manager.config_dir
        active = Mock()
        adapter.processes = {"saved-tunnel": active}
        adapter.log_handles = {"saved-tunnel": Mock()}
        target = adapter.config_dir / "saved-tunnel.toml"
        target.write_bytes(b"BEFORE-MANAGED-REAPPLY")
        target.chmod(0o600)
        with patch.object(adapter, "_resolve_binary_path") as binary:
            with patch.object(adapter, "remove") as remove:
                with self.assertRaisesRegex(RuntimeError, "explicit removal"):
                    adapter.apply("saved-tunnel", SAFE_SPEC.copy())
        binary.assert_not_called()
        remove.assert_not_called()
        active.terminate.assert_not_called()
        self.assertEqual(target.read_bytes(), b"BEFORE-MANAGED-REAPPLY")
        adapter.log_handles["saved-tunnel"].close.assert_not_called()

    async def test_missing_managed_backhaul_binary_cannot_stop_running_tunnel(self):
        # Restart/reapply must not remove a healthy Backhaul just because
        # the pinned executable is missing or unavailable. This is an
        # offline mock: no real process, network port or Docker action.
        from app.core_adapters import BackhaulAdapter
        adapter = object.__new__(BackhaulAdapter)
        adapter.config_dir = self.manager.config_dir
        running = Mock()
        config = adapter.config_dir / "saved-tunnel.toml"
        config.write_bytes(b"PRIVATE_OLD_MANAGED_BACKHAUL_CONFIG\\n")
        config.chmod(0o600)
        previous = config.read_bytes()
        log_handle = Mock()
        adapter.processes = {"saved-tunnel": running}
        adapter.log_handles = {"saved-tunnel": log_handle}
        with patch.object(adapter, "_resolve_binary_path",
                          side_effect=FileNotFoundError("missing")) as resolver:
            with self.assertRaises(FileNotFoundError):
                adapter.apply("saved-tunnel", SAFE_SPEC.copy())
        resolver.assert_called_once_with()
        running.terminate.assert_not_called()
        running.kill.assert_not_called()
        log_handle.close.assert_not_called()
        self.assertIs(adapter.processes["saved-tunnel"], running)
        self.assertIs(adapter.log_handles["saved-tunnel"], log_handle)
        self.assertEqual(config.read_bytes(), previous)
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    async def test_managed_backhaul_binary_preflight_runs_once_before_first_spawn(self):
        from app.core_adapters import BackhaulAdapter
        adapter = object.__new__(BackhaulAdapter)
        adapter.config_dir = self.manager.config_dir
        adapter.processes = {}
        adapter.log_handles = {}
        fake = Mock()
        fake.poll.return_value = None
        with patch.object(adapter, "_resolve_binary_path",
                          return_value=Path("/ci-only/backhaul")) as resolver:
            with patch("app.core_adapters.subprocess.Popen", return_value=fake) as popen:
                with patch("app.core_adapters.time.sleep"):
                    adapter.apply("ci-new-backhaul", SAFE_SPEC.copy())
        resolver.assert_called_once_with()
        popen.assert_called_once()
        self.assertEqual(popen.call_args.args[0],
                         ["/ci-only/backhaul", "-c",
                          str(adapter.config_dir / "ci-new-backhaul.toml")])
        self.assertEqual((adapter.config_dir / "ci-new-backhaul.toml").stat().st_mode & 0o777,
                         0o600)
        self.assertIs(adapter.processes["ci-new-backhaul"], fake)
        adapter.log_handles["ci-new-backhaul"].close()

    async def test_managed_backhaul_server_binary_preflight_preserves_existing(self):
        # The IR (server) role must observe the same pre-stop protection
        # as the Foreign client; never touch a real listener in this test.
        from app.core_adapters import BackhaulAdapter
        adapter = object.__new__(BackhaulAdapter)
        adapter.config_dir = self.manager.config_dir
        running = Mock()
        adapter.processes = {"ir-existing": running}
        handle = Mock()
        adapter.log_handles = {"ir-existing": handle}
        config = adapter.config_dir / "ir-existing.toml"
        config.write_bytes(b"BEFORE-SERVER-REAPPLY")
        config.chmod(0o600)
        server = dict(SAFE_SPEC, mode="server")
        with patch.object(adapter, "_resolve_binary_path",
                          side_effect=FileNotFoundError("missing")) as resolver:
            with self.assertRaises(FileNotFoundError):
                adapter.apply("ir-existing", server)
        resolver.assert_called_once_with()
        running.terminate.assert_not_called()
        running.kill.assert_not_called()
        handle.close.assert_not_called()
        self.assertIs(adapter.processes["ir-existing"], running)
        self.assertEqual(config.read_bytes(), b"BEFORE-SERVER-REAPPLY")

    async def test_signed_node_agent_rejects_invalid_before_adapter(self):
        from app.routers.agent import apply_tunnel as agent_apply, TunnelApply
        from fastapi import HTTPException
        from types import SimpleNamespace
        manager = Mock()
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(adapter_manager=manager))
        )
        with patch("app.routers.agent.require_engine_ready") as ready:
            with self.assertRaises(HTTPException) as blocked:
                await agent_apply(
                    TunnelApply(
                        tunnel_id="saved-tunnel", core="backhaul", type="ws",
                        spec={"mode": "server", "bind_addr": "0.0.0.0:3080"},
                    ),
                    request,
                )
        self.assertEqual(blocked.exception.status_code, 409)
        ready.assert_called_once_with("backhaul")
        manager.apply_tunnel.assert_not_called()

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
