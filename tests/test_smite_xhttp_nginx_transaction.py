"""Offline, isolated transaction tests; NEVER invoke real Nginx, ss, or FRPS."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import smite_xhttp_nginx_transaction as tx


class LocalNginxTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.routes = self.root / "routes"
        self.routes.mkdir(mode=0o700)
        self.bridge = self.root / "bridge.conf"
        self.bridge.write_text(f"include {self.routes}/*.conf;\n")
        self.bridge.chmod(0o600)
        self.lock = self.root / "route.lock"
        self.helper = tx.LocalNginxRouteTransaction(
            route_dir=self.routes, bridge=self.bridge, nginx_binary="fake-nginx"
        )
        self.actions = []
        self.fail_reload = False
        self.frps_pid = 512
        self.frps_ports = frozenset({7000, 45121, 49328, 52000})
        self.config = (
            f"# configuration file {self.bridge}:\n"
            f"include {self.routes}/*.conf;\n"
            "# configuration file /etc/nginx/u-opti-smite-frp-xhttp.conf:\n"
            "location = /45121/www {\n"
            "    proxy_pass http://127.0.0.1:45121;\n"
            "}\n"
            "location ^~ /45121/www/ {\n"
            "    proxy_pass http://127.0.0.1:45121;\n"
            "}\n"
        )

        def fake_run(argv):
            self.actions.append(tuple(argv))
            if argv == ["fake-nginx", "-T"]:
                return self.config
            if argv == ["fake-nginx", "-s", "reload"] and self.fail_reload:
                self.fail_reload = False
                raise tx.RouteTransactionHold("FAKE_RELOAD_FAILED")
            return ""

        def fake_sockets():
            return self.frps_pid, self.frps_ports

        self.patchers = [
            patch.object(tx.os, "geteuid", return_value=0),
            patch.object(tx, "LOCK_FILE", str(self.lock)),
            patch.object(tx, "_run", side_effect=fake_run),
            patch.object(tx, "_frps_socket_inventory", side_effect=fake_sockets),
        ]
        for p in self.patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_preflight_has_no_filesystem_changes_or_nginx_reload(self):
        self.helper.check(49328, "/49328/sso")
        self.assertEqual(list(self.routes.iterdir()), [])
        self.assertFalse(self.lock.exists())
        self.assertNotIn(("fake-nginx", "-s", "reload"), self.actions)

    def test_create_is_exact_prefix_scoped_and_does_not_touch_45121(self):
        self.helper.apply(49328, "/49328/sso")
        target = self.routes / "49328.conf"
        self.assertTrue(target.is_file())
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        content = target.read_text()
        self.assertIn("location = /49328/sso {", content)
        self.assertIn("location ^~ /49328/sso/ {", content)
        self.assertEqual(content.count("proxy_pass http://127.0.0.1:49328;"), 2)
        self.assertNotIn("45121", content)
        self.assertEqual(self.actions.count(("fake-nginx", "-s", "reload")), 1)
        # A repeated apply never overwrites an existing managed file.
        with self.assertRaises(tx.RouteTransactionHold):
            self.helper.apply(49328, "/49328/sso")
        self.assertEqual(target.read_text(), content)

    def test_nginx_reload_failure_removes_only_created_route_and_recovers(self):
        self.fail_reload = True
        with self.assertRaises(tx.RouteTransactionHold):
            self.helper.apply(49328, "/49328/sso")
        self.assertFalse((self.routes / "49328.conf").exists())
        self.assertEqual(self.actions.count(("fake-nginx", "-s", "reload")), 2)

    def test_collision_in_unmanaged_existing_rules_denied(self):
        for existing in (
            "location = /49328/sso { proxy_pass http://127.0.0.1:49111; }\n",
            "location ^~ /49328/sso/a { proxy_pass http://127.0.0.1:49111; }\n",
            "location ^~ /49328/ { proxy_pass http://127.0.0.1:49111; }\n",
            "location = /49222/foo { proxy_pass http://127.0.0.1:49328; }\n",
        ):
            with self.subTest(existing=existing):
                self.config += existing
                with self.assertRaises(tx.RouteTransactionHold):
                    self.helper.check(49328, "/49328/sso")
                self.config = self.config.removesuffix(existing)

    def test_unapproved_bridge_missing_include_and_untrusted_files_hold(self):
        self.bridge.write_text("# nothing approved\n")
        with self.assertRaises(tx.RouteTransactionHold):
            self.helper.check(49328, "/49328/sso")
        self.bridge.write_text(f"include {self.routes}/*.conf;\n")
        self.config = "server { listen 443 ssl; }\n"
        with self.assertRaises(tx.RouteTransactionHold):
            self.helper.check(49328, "/49328/sso")
        self.config = (f"# configuration file {self.bridge}:\n"
                       f"include {self.routes}/*.conf;\n")
        self.bridge.chmod(0o666)
        with self.assertRaises(tx.RouteTransactionHold):
            self.helper.check(49328, "/49328/sso")

    def test_never_overwrite_symlink_or_existing_managed_file(self):
        (self.routes / "49328.conf").symlink_to(self.bridge)
        with self.assertRaises(tx.RouteTransactionHold):
            self.helper.apply(49328, "/49328/sso")
        self.assertEqual(self.bridge.read_text(), f"include {self.routes}/*.conf;\n")

    def test_socket_parser_requires_one_loopback_frps_without_public_bind(self):
        loopback = (
            'LISTEN 0 4096 127.0.0.1:7000 0.0.0.0:* users:(("frps",pid=512,fd=3))\n'
            'LISTEN 0 4096 127.0.0.1:45121 0.0.0.0:* users:(("frps",pid=512,fd=7))\n'
            'LISTEN 0 4096 127.0.0.1:49328 0.0.0.0:* users:(("frps",pid=512,fd=9))\n'
        )
        with patch.object(tx, "_run", return_value=loopback):
            self.assertEqual(tx._frps_socket_inventory(), (512, frozenset({7000, 45121, 49328})))
        public = loopback + (
            'LISTEN 0 4096 0.0.0.0:9999 0.0.0.0:* users:(("frps",pid=512,fd=14))\n'
        )
        with patch.object(tx, "_run", return_value=public):
            with self.assertRaises(tx.RouteTransactionHold):
                tx._frps_socket_inventory()
        mismatch = loopback.replace('pid=512,fd=9', 'pid=123,fd=9')
        with patch.object(tx, "_run", return_value=mismatch):
            self.assertEqual(tx._frps_socket_inventory(), (512, frozenset({7000, 45121})))

    def test_missing_owner_or_control_port_exposure_hold(self):
        self.frps_ports = frozenset({45121, 49328})
        # The signed-ready planner rejects missing control-owner proof first.
        with self.assertRaises(tx.RouteAdmissionDenied):
            self.helper.check(49328, "/49328/sso")
        self.frps_ports = frozenset({7000, 45121, 49328})
        with self.assertRaises(tx.RouteAdmissionDenied):
            self.helper.check(7000, "/7000/control")


if __name__ == "__main__":
    unittest.main()
