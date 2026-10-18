"""Offline FastAPI and Node HTTPS pairing client regression tests.

No live VPS, listening sockets, Docker or tunnel modifications.
"""
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))

from app.routers import auth, node_pairing
from app.config import settings
from app import node_pairing_store

NODE_PATH = ROOT / "node/app/pairing_client.py"
spec = importlib.util.spec_from_file_location("node_pairing_preview_client", NODE_PATH)
node_client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node_client)
ORIGINAL_CLIENT = httpx.Client


class PairingHTTPTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "smite.db"
        self.node_id = "ca1e53fc-00ad-46af-88ad-7ce727700751"
        self.master = Fernet.generate_key().decode("ascii")
        self.ingress = "private-gateway-token-0123456789abcdef-12345678"
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE nodes (id TEXT PRIMARY KEY, metadata TEXT)")
            conn.execute("INSERT INTO nodes (id, metadata) VALUES (?,?)", (
                self.node_id, json.dumps({"role": "foreign", "node_name": "node-kh"})
            ))
        node_pairing_store.initialize_schema(self.db)
        self.previous = (
            settings.db_path,
            settings.smite_node_pairing_preview_enabled,
            settings.smite_node_pairing_master_key,
            settings.smite_node_pairing_ingress_token,
        )
        settings.db_path = str(self.db)
        settings.smite_node_pairing_preview_enabled = False
        settings.smite_node_pairing_master_key = self.master
        settings.smite_node_pairing_ingress_token = self.ingress
        self.addCleanup(self.restore_settings)
        app = FastAPI()
        app.include_router(node_pairing.router, prefix="/api/node-pairing")
        self.app = app
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def restore_settings(self):
        (settings.db_path,
         settings.smite_node_pairing_preview_enabled,
         settings.smite_node_pairing_master_key,
         settings.smite_node_pairing_ingress_token) = self.previous

    def grant_admin(self):
        self.app.dependency_overrides[auth.get_current_user] = (
            lambda: SimpleNamespace(id="admin-pairing-test")
        )

    def issue(self):
        return self.client.post("/api/node-pairing/issue", json={
            "node_id": self.node_id, "role": "foreign", "ttl_seconds": 600
        })

    def redeem(self, code, headers=None):
        return self.client.post("/api/node-pairing/redeem", json={
            "node_id": self.node_id, "role": "foreign",
            "pairing_code": code,
        }, headers=headers or {})

    def test_capabilities_are_admin_only_and_default_off(self):
        response = self.client.get("/api/node-pairing/capabilities")
        self.assertIn(response.status_code, (401, 403))
        self.grant_admin()
        disabled = self.client.get("/api/node-pairing/capabilities")
        self.assertEqual(disabled.status_code, 200)
        self.assertEqual(disabled.headers["cache-control"], "no-store")
        self.assertEqual(disabled.json(), {
            "pairing_preview_enabled": False,
            "legacy_node_auth_enforced": False,
        })

    def test_capabilities_reject_missing_schema_or_invalid_master(self):
        self.grant_admin()
        settings.smite_node_pairing_preview_enabled = True
        ok = self.client.get("/api/node-pairing/capabilities")
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.json()["pairing_preview_enabled"])
        self.assertFalse(ok.json()["legacy_node_auth_enforced"])

        with sqlite3.connect(self.db) as conn:
            conn.execute("DROP TABLE smite_node_identities")
        incomplete = self.client.get("/api/node-pairing/capabilities")
        self.assertFalse(incomplete.json()["pairing_preview_enabled"])

        settings.smite_node_pairing_master_key = "invalid"
        not_configured = self.client.get("/api/node-pairing/capabilities")
        self.assertFalse(not_configured.json()["pairing_preview_enabled"])

    def test_disabled_by_default_and_admin_auth_first(self):
        unauth = self.issue()
        self.assertIn(unauth.status_code, (401, 403))
        self.grant_admin()
        disabled = self.issue()
        self.assertEqual(disabled.status_code, 503)
        self.assertEqual(disabled.headers["cache-control"], "no-store")
        disabled_public = self.redeem("smn1_" + "c" * 40)
        self.assertEqual(disabled_public.status_code, 503)

    def test_admin_issuance_and_443_gateway_proof_then_one_time_redemption(self):
        settings.smite_node_pairing_preview_enabled = True
        unauth = self.issue()
        self.assertIn(unauth.status_code, (401, 403))
        self.grant_admin()
        issued = self.issue()
        self.assertEqual(issued.status_code, 200, issued.text)
        self.assertEqual(issued.headers["cache-control"], "no-store")
        code = issued.json()["pairing_code"]
        self.assertTrue(code.startswith("smn1_"))

        self.assertEqual(self.redeem(code).status_code, 403)
        self.assertEqual(self.redeem(code, {"X-Smite-Pairing-Ingress": "fake"}).status_code, 403)
        success = self.redeem(code, {"X-Smite-Pairing-Ingress": self.ingress})
        self.assertEqual(success.status_code, 200, success.text)
        self.assertEqual(success.headers["cache-control"], "no-store")
        self.assertEqual(success.json()["node_id"], self.node_id)
        secret = success.json()["node_secret"]
        self.assertEqual(len(secret), 64)
        self.assertNotIn(code.encode("ascii"), self.db.read_bytes())
        self.assertNotIn(secret.encode("ascii"), self.db.read_bytes())
        self.assertEqual(
            self.redeem(code, {"X-Smite-Pairing-Ingress": self.ingress}).status_code,
            403,
        )

    def test_bad_configuration_fails_closed(self):
        settings.smite_node_pairing_preview_enabled = True
        self.grant_admin()
        settings.smite_node_pairing_ingress_token = ""
        self.assertEqual(self.issue().status_code, 503)
        settings.smite_node_pairing_ingress_token = self.ingress
        settings.smite_node_pairing_master_key = "changeme"
        self.assertEqual(self.issue().status_code, 503)

    def test_wrong_role_cannot_consume_code(self):
        settings.smite_node_pairing_preview_enabled = True
        self.grant_admin()
        issued = self.issue()
        self.assertEqual(issued.status_code, 200)
        code = issued.json()["pairing_code"]
        bad = self.client.post("/api/node-pairing/redeem", json={
            "node_id": self.node_id, "role": "iran",
            "pairing_code": code,
        }, headers={"X-Smite-Pairing-Ingress": self.ingress})
        self.assertEqual(bad.status_code, 403)
        good = self.redeem(code, {"X-Smite-Pairing-Ingress": self.ingress})
        self.assertEqual(good.status_code, 200)


class NodeClientTest(unittest.TestCase):
    def test_url_restrictions(self):
        for url in (
            "http://panel.example.com",
            "https://panel.example.com:8443",
            "https://user:pass@panel.example.com",
            "https://panel.example.com/other",
            "https://panel.example.com?code=secret",
            "https://panel.example.com/#key",
        ):
            with self.subTest(url=url), self.assertRaises(node_client.PairingClientError):
                node_client._endpoint(url)
        self.assertEqual(node_client._endpoint("https://panel.example.com"),
                         "https://panel.example.com/api/node-pairing/redeem")

    def test_tls_verified_exchange_and_no_overwrite_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            private = Path(folder) / "identities"
            private.mkdir(mode=0o700)
            file = private / "node.json"
            secret = "f" * 64
            node_id = "bbbbbbbb-1111-2222-3333-444444444444"
            calls = []

            def handler(request: httpx.Request):
                self.assertEqual(request.url.scheme, "https")
                self.assertEqual(request.url.port, None)
                self.assertEqual(request.url.path, "/api/node-pairing/redeem")
                payload = json.loads(request.read())
                self.assertEqual(payload["pairing_code"], "smn1_" + "x" * 42)
                return httpx.Response(
                    200, json={"node_id": node_id, "node_secret": secret}
                )

            def make_client(**kwargs):
                calls.append(kwargs)
                return ORIGINAL_CLIENT(
                    transport=httpx.MockTransport(handler),
                    follow_redirects=kwargs["follow_redirects"],
                )

            with patch.object(node_client.httpx, "Client", side_effect=make_client):
                out = node_client.redeem_and_store(
                    panel_url="https://panel.example.com",
                    pairing_code="smn1_" + "x" * 42,
                    node_id=node_id, role="foreign",
                    destination=file,
                )
            self.assertEqual(out, node_id)
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(file.read_text())["node_secret"], secret)
            self.assertTrue(calls[0]["verify"])
            self.assertFalse(calls[0]["follow_redirects"])
            self.assertFalse(calls[0]["trust_env"])
            with self.assertRaises(node_client.PairingClientError):
                node_client.redeem_and_store(
                    panel_url="https://panel.example.com",
                    pairing_code="smn1_" + "x" * 42,
                    node_id=node_id, role="foreign", destination=file,
                )

    def test_insecure_storage_rejected_without_network_call(self):
        with tempfile.TemporaryDirectory() as folder:
            private = Path(folder) / "wrong-mode"
            private.mkdir(mode=0o755)
            file = private / "node.json"
            with patch.object(node_client.httpx, "Client") as network:
                with self.assertRaises(node_client.PairingClientError):
                    node_client.redeem_and_store(
                        panel_url="https://panel.example.com",
                        pairing_code="smn1_" + "x" * 42,
                        node_id="node-abcdefgh", role="iran", destination=file,
                    )
                network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
