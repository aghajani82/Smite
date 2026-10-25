"""Offline fail-closed signed FRPS port-7000 admission tests.

Pure synthetic socket fixtures. Never inspect or change the runner's live
listeners and never start frps or rewrite a config.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import psutil

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "node/app/frp_singleton_guard.py"
spec = importlib.util.spec_from_file_location("frp_singleton_guard_test", HELPER)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def listener(port: int, ip: str = "127.0.0.1", status: str = psutil.CONN_LISTEN):
    return SimpleNamespace(laddr=SimpleNamespace(ip=ip, port=port), status=status)


class FrpsSingletonSlotTests(unittest.TestCase):
    def check(self, *, sockets=(), shared_frps_owner=None, control_port=7000):
        return guard.assert_frps_control_port_available(
            tunnel_id="trial-frp-49328",
            control_port=control_port,
            shared_frps_owner=shared_frps_owner,
            sockets=sockets,
        )

    def test_absent_listener_allows_first_server_without_writes(self):
        self.assertIsNone(self.check())
        self.assertIsNone(self.check(sockets=[listener(45121)]))

    def test_existing_7000_listener_blocks_new_server(self):
        for ip in ("127.0.0.1", "0.0.0.0", "::", "::1"):
            with self.subTest(ip=ip):
                with self.assertRaisesRegex(
                    guard.FrpsServerSlotDenied, "already listening"
                ):
                    self.check(sockets=[listener(7000, ip=ip)])

    def test_only_tcp_listeners_are_conflicts(self):
        self.assertIsNone(
            self.check(sockets=[listener(7000, status=psutil.CONN_ESTABLISHED)])
        )

    def test_child_marker_can_never_be_sent_as_server(self):
        with self.assertRaisesRegex(
            guard.FrpsServerSlotDenied, "cannot start"
        ):
            self.check(shared_frps_owner="trial-frp-45121")

    def test_only_approved_control_port_accepted(self):
        for v in (0, 443, 7001, True, None, "not-a-port"):
            with self.subTest(port=v):
                with self.assertRaises(guard.FrpsServerSlotDenied):
                    self.check(control_port=v)

    def test_socket_scan_failure_fails_closed(self):
        with patch.object(
            guard.psutil, "net_connections",
            side_effect=psutil.AccessDenied(pid=10, name="test")
        ):
            with self.assertRaisesRegex(
                guard.FrpsServerSlotDenied, "Cannot verify"
            ):
                guard.assert_frps_control_port_available(
                    tunnel_id="trial-frp-49328", control_port=7000
                )

    def test_adapter_manager_checks_before_removing_working_owner(self):
        source = (ROOT / "node/app/core_adapters.py").read_text()
        segment = source.split("class AdapterManager:", 1)[1]
        method = segment.split("    async def apply_tunnel(", 1)[1].split(
            "    async def remove_tunnel(", 1
        )[0]
        guard_pos = method.index("assert_frps_control_port_available(")
        destructive_pos = method.index("await self.remove_tunnel(tunnel_id)")
        self.assertLess(guard_pos, destructive_pos)

    def test_no_secret_leaks_in_errors(self):
        try:
            self.check(shared_frps_owner="token-private-should-not-appear")
        except guard.FrpsServerSlotDenied as exc:
            self.assertNotIn("token-private-should-not-appear", str(exc))
        else:
            self.fail("Expected denial")

    def test_adapter_guards_before_any_existing_process_remove_or_write(self):
        # Inspect the exact source order as an explicit guard contract; no
        # adapter startup/side effects are exercised by this offline test.
        source = (ROOT / "node/app/core_adapters.py").read_text()
        segment = source.split("class FrpAdapter:", 1)[1].split(
            "class GostAdapter:", 1
        )[0]
        apply = segment.split("    def apply(", 1)[1].split("    def remove(", 1)[0]
        guard_pos = apply.index("assert_frps_control_port_available(")
        remove_pos = apply.index("self.remove(tunnel_id)")
        config_pos = apply.index("with open(config_file, 'w')")
        self.assertLess(guard_pos, remove_pos)
        self.assertLess(guard_pos, config_pos)
        self.assertNotIn(
            'logger.info(f"FRP tunnel {tunnel_id} received spec: {spec}")',
            apply,
        )


if __name__ == "__main__":
    unittest.main()
