"""Offline signed Panel NodeClient transport tests; no VPS/real network.

Exercises the LIVE NodeClient signed opt-in branch, real encrypted pairing
store lookup and exact HTTPX bytes/headers. Legacy mode and Node containers
are untouched.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))

from app import node_auth, node_pairing_store
from app.config import settings
from app.signed_agent_transport import (
    SignedAgentUnavailable, get_paired_key, signed_agent_call,
    validate_agent_origin,
)
from app.node_client import NodeClient


class SignedTransportTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = Path(self.temp.name) / "smite.db"
        self.master = Fernet.generate_key().decode("ascii")
        self.node_id = "b3bfbd2e-3247-4f04-b74c-c22a164b0312"
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE nodes (id TEXT PRIMARY KEY, metadata TEXT)")
            db.execute("INSERT INTO nodes(id,metadata) VALUES (?,?)", (
                self.node_id, json.dumps({"role": "foreign"}),
            ))
        node_pairing_store.initialize_schema(self.db_path)
        issued = node_pairing_store.issue_code(
            self.db_path, master_key=self.master,
            node_id=self.node_id, role="foreign", admin_id="trustedadmin",
        )
        paired = node_pairing_store.redeem_code(
            self.db_path, master_key=self.master, code=issued.code,
            node_id=self.node_id, role="foreign",
        )
        self.secret = paired.secret.encode("ascii")
        self.prior = (
            settings.db_path,
            settings.smite_node_pairing_master_key,
            settings.smite_panel_agent_auth_mode,
        )
        settings.db_path = str(self.db_path)
        settings.smite_node_pairing_master_key = self.master
        settings.smite_panel_agent_auth_mode = "signed"
        self.addCleanup(self.restore)

    def restore(self):
        (settings.db_path, settings.smite_node_pairing_master_key,
         settings.smite_panel_agent_auth_mode) = self.prior

    def test_key_reads_encrypted_store_and_refuses_revocation(self):
        self.assertEqual(get_paired_key(node_id=self.node_id), self.secret)
        raw = self.db_path.read_bytes()
        self.assertNotIn(self.secret, raw)
        self.assertNotIn(self.master.encode(), raw)
        self.assertTrue(node_pairing_store.revoke_node(self.db_path, node_id=self.node_id))
        with self.assertRaises(SignedAgentUnavailable):
            get_paired_key(node_id=self.node_id)

    def test_missing_key_or_db_refused(self):
        settings.smite_node_pairing_master_key = ""
        with self.assertRaises(SignedAgentUnavailable):
            get_paired_key(node_id=self.node_id)
        settings.smite_node_pairing_master_key = self.master
        settings.db_path = str(self.db_path.parent / "does-not-exist.sqlite3")
        with self.assertRaises(SignedAgentUnavailable):
            get_paired_key(node_id=self.node_id)
        self.assertFalse(Path(settings.db_path).exists())

    def test_restrict_transport_to_https_443_and_explicit_loopback(self):
        self.assertEqual(
            validate_agent_origin("https://kh.example.net", using_frp=False),
            "https://kh.example.net:443",
        )
        self.assertEqual(
            validate_agent_origin("https://kh.example.net:443/", using_frp=False),
            "https://kh.example.net:443",
        )
        self.assertEqual(
            validate_agent_origin("http://127.0.0.1:18081", using_frp=True),
            "http://127.0.0.1:18081",
        )
        self.assertEqual(
            validate_agent_origin("http://127.0.0.1:8888", using_frp=False),
            "http://127.0.0.1:8888",
        )
        for address, frp in (
            ("http://kh.example.net:8888", False),
            ("http://91.107.185.50:8888", False),
            ("https://kh.example.net:8443", False),
            ("https://91.107.185.50", False),
            ("https://kh.example.net/path", False),
            ("https://user:pw@kh.example.net", False),
            ("https://kh.example.net/?token=secret", False),
            ("https://kh.example.net", True),
            ("http://localhost:8888", False),
            ("http://127.0.0.1:9000", False),
            ("http://127.0.0.2:8888", False),
            ("ftp://kh.example.net:443", False),
        ):
            with self.subTest(address=address, frp=frp):
                with self.assertRaises(SignedAgentUnavailable):
                    validate_agent_origin(address, using_frp=frp)

    async def test_signed_apply_sends_exact_bytes_over_verified_https(self):
        seen = []
        self_test = self
        class Response:
            is_redirect = False
            def raise_for_status(self):
                pass
            def json(self):
                return {"status": "success", "message": "Tunnel applied"}
        class FakeHttpx:
            def __init__(self, **kwargs):
                seen.append(("init", kwargs))
            async def __aenter__(self):
                return self
            async def __aexit__(self, *_):
                return None
            async def request(self, method, url, *, content, headers):
                self_test.assertEqual(method, "POST")
                self_test.assertEqual(url, "https://kh.example.net:443/api/agent/tunnels/apply")
                self_test.assertEqual(headers.get("Content-Type"), "application/json")
                data = json.loads(content)
                self_test.assertEqual(data["tunnel_id"], "demo-frp")
                self_test.assertTrue(node_auth.verify_request(
                    secret=self_test.secret, node_id=self_test.node_id,
                    method=method, target="/api/agent/tunnels/apply",
                    body=content, headers=headers, replay=node_auth.NonceWindow(),
                ))
                self_test.assertNotIn(self_test.secret, content)
                seen.append(("request", method, url, content))
                return Response()

        payload = {"core": "frp", "type": "tcp", "tunnel_id": "demo-frp", "spec": {"local": 8081}}
        with patch("app.signed_agent_transport.httpx.AsyncClient", FakeHttpx):
            result = await signed_agent_call(
                node_id=self.node_id, address="https://kh.example.net",
                using_frp=False, method="POST",
                target="/api/agent/tunnels/apply", payload=payload,
            )
        self.assertEqual(result["status"], "success")
        self.assertTrue(seen[0][1]["verify"])
        self.assertFalse(seen[0][1]["trust_env"])
        self.assertFalse(seen[0][1]["follow_redirects"])
        self.assertEqual(len([x for x in seen if x[0] == "request"]), 1)

    async def test_signed_get_status_via_loopback_frp(self):
        recorded = []
        class Response:
            is_redirect = False
            def raise_for_status(self): pass
            def json(self): return {"status": "ok", "active_tunnels": 0}
        class FakeHttpx:
            def __init__(self, **kwargs): recorded.append(("init", kwargs))
            async def __aenter__(self): return self
            async def __aexit__(self, *_): return None
            async def request(self, method, url, *, content, headers):
                self_test.assertEqual(content, b"")
                self_test.assertEqual(url, "http://127.0.0.1:18081/api/agent/status")
                self_test.assertTrue(node_auth.verify_request(
                    secret=self_test.secret, node_id=self_test.node_id,
                    method=method, target="/api/agent/status",
                    body=content, headers=headers, replay=node_auth.NonceWindow(),
                ))
                recorded.append(("request", method))
                return Response()
        self_test = self
        with patch("app.signed_agent_transport.httpx.AsyncClient", FakeHttpx):
            result = await signed_agent_call(
                node_id=self.node_id, address="http://127.0.0.1:18081",
                using_frp=True, method="GET", target="/api/agent/status",
                timeout=3.0,
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(recorded[-1], ("request", "GET"))

    async def test_signed_mode_is_wired_to_real_nodeclient_and_never_downgrades(self):
        client = NodeClient()
        signed = AsyncMock(return_value={"status": "success"})
        with patch.object(client, "_signed_agent_request", signed):
            data = await client.send_to_node(
                self.node_id, "/api/agent/tunnels/remove", {"tunnel_id": "demo"}
            )
            self.assertEqual(data["status"], "success")
            signed.assert_awaited_once_with(
                self.node_id, method="POST",
                target="/api/agent/tunnels/remove", payload={"tunnel_id": "demo"}
            )
            signed.reset_mock()
            result = await client.get_tunnel_status(self.node_id, "demo")
            self.assertEqual(result["status"], "success")
            signed.assert_awaited_once_with(
                self.node_id, method="GET", target="/api/agent/status",
                timeout=3.0,
            )
            signed.reset_mock()
            denied = await client.send_to_node(
                self.node_id, "/api/other", {}
            )
            self.assertEqual(denied["status"], "error")
            signed.assert_not_awaited()

    async def test_transport_denied_before_any_network(self):
        with patch("app.signed_agent_transport.httpx.AsyncClient") as network:
            with self.assertRaises(SignedAgentUnavailable):
                await signed_agent_call(
                    node_id=self.node_id,
                    address="http://91.107.185.50:8888", using_frp=False,
                    method="GET", target="/api/agent/status",
                )
            network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
