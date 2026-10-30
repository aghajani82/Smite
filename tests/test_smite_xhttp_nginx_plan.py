"""Offline policy tests for auto XHTTP Nginx route planning (no root)."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from smite_xhttp_nginx_plan import plan_xhttp_nginx_route, RouteAdmissionDenied


class XhttpNginxPlannerTests(unittest.TestCase):
    def setUp(self):
        self.inbound = {
            "port": 49328, "path": "/49328/sso", "network": "xhttp",
            "protocol": "vless", "listen": "127.0.0.1", "enabled": True,
        }
        self.routes = {"/45121/www": 45121}
        self.listeners = {7000, 45121, 49328}

    def plan(self, **override):
        return plan_xhttp_nginx_route(
            {**self.inbound, **override},
            registered_routes=self.routes,
            frps_listener_ports=self.listeners,
        )

    def test_preserves_both_exact_and_prefix_paths_and_loopback(self):
        result = self.plan()
        self.assertEqual(result.exact_location, "/49328/sso")
        self.assertEqual(result.prefix_location, "/49328/sso/")
        self.assertFalse(result.already_present)
        self.assertIn("location = /49328/sso {", result.snippet)
        self.assertIn("location ^~ /49328/sso/ {", result.snippet)
        self.assertEqual(result.snippet.count("proxy_pass http://127.0.0.1:49328;"), 2)
        self.assertNotIn("proxy_pass http://127.0.0.1:49328/;", result.snippet)
        self.assertIn("proxy_request_buffering off;", result.snippet)

    def test_repeated_identical_route_is_idempotently_classified(self):
        self.routes["/49328/sso"] = 49328
        self.assertTrue(self.plan().already_present)

    def test_conflicts_with_existing_port_or_overlapping_prefix_fail_closed(self):
        for routes in (
            {"/49328/other": 49328},
            {"/49328/sso": 45121},
            {"/49328": 45678},
            {"/49328/sso/further": 47000},
        ):
            with self.subTest(routes=routes):
                self.routes = routes
                with self.assertRaises(RouteAdmissionDenied):
                    self.plan()

    def test_rejects_unapproved_inputs_or_missing_singleton(self):
        for params in (
            {"port": True},
            {"port": 999},
            {"path": "/49328/../sso"},
            {"path": "/49328/sso;return 200"},
            {"path": "/49328/sso?malicious=1"},
            {"path": "/49328/sso/"},
            {"path": "/api/sso"},
            {"listen": "0.0.0.0"},
            {"network": "ws"},
            {"protocol": "trojan"},
            {"enabled": 1},
        ):
            with self.subTest(params=params), self.assertRaises(RouteAdmissionDenied):
                self.plan(**params)
        self.listeners = {7000, 45121}
        with self.assertRaises(RouteAdmissionDenied):
            self.plan()
        self.listeners = {45121, 49328}
        with self.assertRaises(RouteAdmissionDenied):
            self.plan()

    def test_custom_canonical_paths_and_reserved_names(self):
        for path in ("/connect", "/custom/connect", "/45121/sso"):
            self.assertEqual(self.plan(path=path).path,path)
        for path in ("/api/foo","/admin","/login","/assets/v1", "/a%2fb", "/a//b", "/a/../b", "/a\\b", "/a#b", "/a;b", "/a b", "/a/", "/"):
            with self.subTest(path=path),self.assertRaises(RouteAdmissionDenied): self.plan(path=path)


if __name__ == "__main__":
    unittest.main()
