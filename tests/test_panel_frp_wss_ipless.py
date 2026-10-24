#!/usr/bin/env python3
"""Offline, no-Docker unit and source-contract tests for signed FRP WSS fix."""
import ast
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "panel/app/frp_wss_panel.py"
ROUTER = ROOT / "panel/app/routers/tunnels.py"
CONFIG = ROOT / "panel/app/config.py"

spec = importlib.util.spec_from_file_location("trial_wss_target", HELPER)
resolver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resolver)

DEFAULT = dict(
    wss_enabled=True,
    signed_panel=True,
    managed_engines=True,
    panel_domain="ir.kolbe1.ir",
    bind_port=7000,
    tunnel_type="tcp",
)


class FrpPanelTrustedAddressTest(unittest.TestCase):
    def test_signed_wss_without_iran_ip_uses_reviewed_domain(self):
        self.assertEqual(resolver.resolve_frp_target(None, **DEFAULT),
                         "ir.kolbe1.ir")
        self.assertEqual(resolver.resolve_frp_target("", **DEFAULT),
                         "ir.kolbe1.ir")
        self.assertEqual(resolver.resolve_frp_target("untrusted.node.ip", **DEFAULT),
                         "ir.kolbe1.ir")

    def test_legacy_no_ip_rejects_bypass(self):
        self.assertIsNone(resolver.resolve_frp_target(
            None, **dict(DEFAULT, wss_enabled=False)
        ))
        self.assertEqual(resolver.resolve_frp_target(
            "192.0.2.10", **dict(DEFAULT, wss_enabled=False, panel_domain="")
        ), "192.0.2.10")

    def test_cannot_opt_in_without_signed_managed_admission(self):
        for key in ("signed_panel", "managed_engines"):
            with self.subTest(key=key), self.assertRaisesRegex(
                resolver.FrpWssTargetError, "signed managed"
            ):
                resolver.resolve_frp_target(None, **dict(DEFAULT, **{key: False}))

    def test_reject_empty_spoofed_or_unsafe_control_domain(self):
        for bad in (
            "", "localhost", "127.0.0.1", "::1", "https://ir.kolbe1.ir",
            "ir.kolbe1.ir:443", "ir.kolbe1.ir.", ".ir.kolbe1.ir",
            "ir..kolbe1.ir", "ir.kolbe1.ir/path",
            "ir.kolbe1.ir?host=other", "ir.kolbe1.ir ",
            " ir.kolbe1.ir", "-bad.example", "foo_.example",
        ):
            with self.subTest(domain=bad), self.assertRaisesRegex(
                resolver.FrpWssTargetError, "PANEL_DOMAIN"
            ):
                resolver.resolve_frp_target(
                    None, **dict(DEFAULT, panel_domain=bad)
                )

    def test_wss_control_port_only_7000(self):
        for bad in (0, 7001, None, "7000.0", "07000", 443, True):
            with self.subTest(port=bad), self.assertRaisesRegex(
                resolver.FrpWssTargetError, "bind port 7000"
            ):
                resolver.resolve_frp_target(
                    None, **dict(DEFAULT, bind_port=bad)
                )
        self.assertEqual(resolver.resolve_frp_target(
            None, **dict(DEFAULT, bind_port="7000")
        ), "ir.kolbe1.ir")

    def test_wss_trial_tcp_only(self):
        for mode in ("udp", "ws", "tcp-mux", ""):
            with self.subTest(mode=mode), self.assertRaisesRegex(
                resolver.FrpWssTargetError, "TCP only"
            ):
                resolver.resolve_frp_target(
                    None, **dict(DEFAULT, tunnel_type=mode)
                )

    def test_create_and_reapply_use_same_trusted_resolver(self):
        source = ROUTER.read_text(encoding="utf-8")
        tree = ast.parse(source)
        create = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)
                      and n.name == "create_tunnel")
        reapply = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)
                       and n.name == "apply_tunnel")
        calls = lambda fn: sum(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "_trusted_frp_control_target"
            for n in ast.walk(fn)
        )
        self.assertEqual(calls(create), 1)
        self.assertEqual(calls(reapply), 1)
        self.assertEqual(source.count("FRP WSS requires KH local IP 127.0.0.1"), 2)
        self.assertIn('server_spec["bind_port"] = bind_port', source)
        self.assertIn('client_spec["server_port"] = bind_port', source)
        self.assertIn('wss_enabled=settings.smite_frp_standard_wss', source)
        self.assertIn('managed_engines=settings.smite_engine_management_mode == "managed"', source)
        self.assertIn('signed_panel=settings.smite_panel_agent_auth_mode == "signed"', source)
        self.assertIn('panel_domain=settings.panel_domain', source)
        self.assertEqual(source.count('error_message = "Iran node has no IP address"'), 8)

    def test_legacy_spec_edit_path_cannot_start_panel_frp_when_wss_active(self):
        source = ROUTER.read_text(encoding="utf-8")
        tree = ast.parse(source)
        update = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)
                      and n.name == "update_tunnel")
        decision = next(n for n in ast.walk(update)
                        if isinstance(n, ast.If) and "settings.smite_frp_standard_wss"
                        in ast.unparse(n.test)
                        and "spec_changed" in ast.unparse(n.test))
        self.assertIn("raise HTTPException", ast.unparse(decision))
        self.assertEqual(decision.body[0].exc.func.id, "HTTPException")

    def test_overlay_image_only_changes_reviewed_panel_sources(self):
        dockerfile = (ROOT / "panel/Dockerfile.rc2-wss-overlay").read_text(
            encoding="utf-8")
        self.assertIn("FROM ${PANEL_BASE_IMAGE}", dockerfile)
        source_copies = [
            line for line in dockerfile.splitlines()
            if line.startswith("COPY ")
        ]
        self.assertEqual(len(source_copies), 3)
        for expected in (
            "panel/app/frp_wss_panel.py /app/app/frp_wss_panel.py",
            "panel/app/config.py /app/app/config.py",
            "panel/app/routers/tunnels.py /app/app/routers/tunnels.py",
        ):
            self.assertTrue(any(expected in line for line in source_copies))
        self.assertNotIn("ghcr.io/zzedix", dockerfile)
        self.assertNotIn("pip install", dockerfile)
        self.assertNotIn("npm install", dockerfile)

    def test_flag_default_off_and_only_router_uses_explicit_setting(self):
        self.assertIn('smite_frp_standard_wss: bool = False',
                      CONFIG.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
