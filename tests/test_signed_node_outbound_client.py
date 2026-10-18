"""Offline Node->Panel strict HTTPS signed client and legacy isolation tests."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "node"))

from app.config import settings
from app import node_auth, signed_panel_client

# Legacy FRP manager creates /etc/smite-node/frp_comm during module import.
# A CI runner must never require root or write host files just to test signed
# registration. Provide a fake FRP module before importing PanelClient.
fake_frp = types.ModuleType("app.frp_comm_client")
fake_frp.frp_comm_client = Mock()
fake_frp.frp_comm_client.is_running.return_value = False
sys.modules["app.frp_comm_client"] = fake_frp

from app.panel_client import PanelClient


class SignedNodeClientTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        private = Path(self.work.name) / "identity"
        private.mkdir(mode=0o700)
        self.identity = private / "node.json"
        self.uuid = "b3bfbd2e-3247-4f04-b74c-c22a164b0312"
        self.secret = "f" * 64
        self.identity.write_text(json.dumps({
            "node_id": self.uuid, "node_secret": self.secret,
        }))
        self.identity.chmod(0o600)
        self.prior = (
            settings.panel_address, settings.smite_agent_identity_path,
            settings.smite_node_panel_auth_mode, settings.node_role,
        )
        settings.panel_address = "panel.example.org:443"
        settings.smite_agent_identity_path = str(self.identity)
        settings.smite_node_panel_auth_mode = "signed"
        settings.node_role = "foreign"
        self.addCleanup(self.restore)

    def restore(self):
        (settings.panel_address, settings.smite_agent_identity_path,
         settings.smite_node_panel_auth_mode, settings.node_role) = self.prior

    def test_https_hostname_policy(self):
        self.assertEqual(
            signed_panel_client.validated_panel_origin("panel.example.org:443"),
            "https://panel.example.org:443",
        )
        self.assertEqual(
            signed_panel_client.validated_panel_origin("https://panel.example.org/"),
            "https://panel.example.org:443",
        )
        for bad in (
            "http://panel.example.org:8000", "https://91.107.174.237:443",
            "https://panel.example.org:8000", "https://user:pass@panel.example.org",
            "https://panel.example.org/api/nodes", "https://panel.example.org?key=secret",
            "panel.example.org:bad", "https://localhost:443",
        ):
            with self.subTest(value=bad):
                with self.assertRaises(signed_panel_client.SignedPanelUnavailable):
                    signed_panel_client.validated_panel_origin(bad)

    async def test_exact_signed_post_and_verified_tls(self):
        sent = []
        original = self
        class Response:
            status_code = 200
            is_redirect = False
            def raise_for_status(self): pass
            def json(self):
                return {"id": original.uuid, "status": "active", "metadata": {}}

        class Client:
            def __init__(self, **kwargs):
                sent.append(("init", kwargs))
            async def __aenter__(self): return self
            async def __aexit__(self, *_): return None
            async def post(self, url, *, content, headers):
                original.assertEqual(
                    url, "https://panel.example.org:443/api/node-control/register"
                )
                original.assertEqual(
                    json.loads(content),
                    {"node_id": original.uuid, "role": "foreign"},
                )
                original.assertTrue(node_auth.verify_request(
                    secret=original.secret.encode(), node_id=original.uuid,
                    method="POST", target="/api/node-control/register",
                    body=content, headers=headers, replay=node_auth.NonceWindow(),
                ))
                sent.append(("post", content))
                return Response()

        with patch.object(signed_panel_client.httpx, "AsyncClient", Client):
            result = await signed_panel_client.signed_register()
        self.assertEqual(result["id"], self.uuid)
        self.assertTrue(sent[0][1]["verify"])
        self.assertFalse(sent[0][1]["trust_env"])
        self.assertFalse(sent[0][1]["follow_redirects"])
        self.assertEqual(len([s for s in sent if s[0] == "post"]), 1)

    async def test_no_invalid_hostname_or_role_can_issue_request(self):
        with patch.object(signed_panel_client.httpx, "AsyncClient") as network:
            settings.panel_address = "http://panel.example.org:8000"
            with self.assertRaises(signed_panel_client.SignedPanelUnavailable):
                await signed_panel_client.signed_register()
            settings.panel_address = "panel.example.org:443"
            with self.assertRaises(signed_panel_client.SignedPanelUnavailable):
                await signed_panel_client.signed_panel_post(
                    target="/api/node-control/frp-status",
                    data={"node_id": "wrong-node-id", "connected": True}
                )
            network.assert_not_called()

    async def test_node_runtime_register_and_heartbeat_do_not_use_legacy_client(self):
        client = PanelClient()
        with patch.object(client, "_generate_fingerprint", AsyncMock()):
            await client.start()
        self.assertIsNone(client.client)
        with patch("app.panel_client.signed_register",
                   AsyncMock(return_value={
                       "id": self.uuid, "status": "active", "metadata": {},
                   })) as new_register:
            with patch("app.panel_client.frp_comm_client.is_running", return_value=False):
                success = await client.register_with_panel()
        self.assertTrue(success)
        self.assertEqual(client.node_id, self.uuid)
        new_register.assert_awaited_once()

        with patch("app.panel_client.signed_frp_status",
                   AsyncMock(return_value={"status": "success"})) as heartbeat:
            await client._report_frp_status(18476)
        heartbeat.assert_awaited_once_with(connected=True, remote_port=18476)

        with patch("app.panel_client.signed_register",
                   AsyncMock(side_effect=Exception("signed failed"))) as failed:
            self.assertFalse(await client.register_with_panel())
        failed.assert_awaited_once()
        self.assertIsNone(client.client)


if __name__ == "__main__":
    unittest.main()
