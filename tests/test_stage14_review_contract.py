"""Stage14: static/offline security protocol contract, NEVER deployment approval."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "release/stage14-review-contract.json"
UUID = "bbbbbbbb-1111-2222-3333-444444444444"
SECRET = b"f" * 64


def load_file(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseContractTest(unittest.TestCase):
    def test_release_is_an_unpublished_development_proposal(self):
        manifest = json.loads(CONTRACT.read_text())
        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(manifest["release"]["proposed_version"], "2.0.0-rc.0")
        self.assertFalse(manifest["release"]["published"])
        self.assertFalse(manifest["release"]["tag_created"])
        self.assertFalse(manifest["release"]["production_deployable"])
        self.assertFalse(manifest["activation_allowed"])
        self.assertFalse(manifest["environment"]["auto_merge"])
        self.assertFalse(manifest["environment"]["auto_enable"])
        self.assertEqual(manifest["integration"]["upstream_prs"], list(range(1, 13)))
        self.assertEqual(manifest["integration"]["uopti_admin_overlay_sibling_pr"], 27)
        self.assertGreaterEqual(len(manifest["holds"]), 8)

    def test_panel_node_hmac_source_identical_and_interoperate(self):
        left = ROOT / "panel/app/node_auth.py"
        right = ROOT / "node/app/node_auth.py"
        self.assertEqual(left.read_bytes(), right.read_bytes())
        panel = load_file(left, "stage14_panel_hmac")
        node = load_file(right, "stage14_node_hmac")
        contract = json.loads(CONTRACT.read_text())
        self.assertEqual(panel.VERSION, node.VERSION)
        self.assertEqual(panel.VERSION, contract["protocol"]["envelope"])
        body = b'{"node_id":"bbbbbbbb-1111-2222-3333-444444444444"}'
        moment = int(time.time())
        headers = panel.sign_request(
            secret=SECRET, node_id=UUID, method="POST",
            target="/api/node-control/register", body=body,
            timestamp=moment, nonce="a" * 32,
        )
        replay = node.NonceWindow()
        self.assertTrue(node.verify_request(
            secret=SECRET, node_id=UUID, method="POST",
            target="/api/node-control/register", body=body,
            headers=headers, replay=replay, now=moment,
        ))
        self.assertFalse(node.verify_request(
            secret=SECRET, node_id=UUID, method="POST",
            target="/api/node-control/register", body=body,
            headers=headers, replay=replay, now=moment,
        ))
        self.assertFalse(panel.verify_request(
            secret=SECRET, node_id=UUID, method="POST",
            target="/api/node-control/register", body=body + b" ",
            headers=headers, replay=panel.NonceWindow(), now=moment,
        ))
        new_headers = node.sign_request(
            secret=SECRET, node_id=UUID, method="GET",
            target="/api/agent/status", body=b"",
            timestamp=moment, nonce="b" * 32,
        )
        self.assertTrue(panel.verify_request(
            secret=SECRET, node_id=UUID, method="GET",
            target="/api/agent/status", body=b"",
            headers=new_headers, replay=panel.NonceWindow(), now=moment,
        ))

    def test_protocol_routes_and_default_off_settings_are_present(self):
        manifest = json.loads(CONTRACT.read_text())
        panel_cfg = (ROOT / "panel/app/config.py").read_text()
        node_cfg = (ROOT / "node/app/config.py").read_text()
        self.assertIn('smite_panel_agent_auth_mode: Literal["legacy", "signed"] = "legacy"', panel_cfg)
        self.assertIn('smite_node_registration_mode: Literal["legacy", "signed"] = "legacy"', panel_cfg)
        self.assertIn('smite_node_panel_auth_mode: Literal["legacy", "signed", "paused"] = "legacy"', node_cfg)
        # Pending pairing must never change the historic default or permit
        # legacy HTTP/8000 registration for an explicitly paused Node.
        client = (ROOT / "node/app/panel_client.py").read_text()
        self.assertIn('if settings.smite_node_panel_auth_mode == "paused":', client)
        self.assertIn("outbound Panel registration is paused", client)
        self.assertIn('smite_agent_auth_mode: Literal["legacy", "strict"] = "legacy"', node_cfg)
        inbound = (ROOT / "panel/app/routers/signed_nodes.py").read_text()
        agent = (ROOT / "node/app/routers/agent.py").read_text()
        panel = (ROOT / "panel/app/node_client.py").read_text()
        outbound = (ROOT / "node/app/signed_panel_client.py").read_text()
        for route in ("register", "frp-status", "gateway-check"):
            self.assertIn(f'@router.post("/{route}")', inbound)
        for path in manifest["protocol"]["node_signed_targets"]:
            self.assertIn(path, (ROOT / "panel/app/signed_node_registration.py").read_text() + outbound)
        for method in ("apply", "remove"):
            self.assertIn(f'/api/agent/tunnels/{method}', panel)
        self.assertIn("require_agent_auth", agent)
        self.assertIn('pin = approved_node(node_id)', panel)
        self.assertIn('prepare_node_command(node_id, endpoint, data)', panel)
        self.assertIn('verify=True, trust_env=False, follow_redirects=False', outbound)

    def test_no_automatic_upgrade_or_release_action(self):
        review = CONTRACT.read_text()
        self.assertNotIn('"activation_allowed": true', review)
        self.assertNotIn('"published": true', review)
        self.assertNotIn('"tag_created": true', review)
        self.assertIn("trusted ingress injection", review)


if __name__ == "__main__":
    unittest.main()
