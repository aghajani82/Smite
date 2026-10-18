"""Stage12 offline tests: pinned signed target, control URL, Backhaul edit gate.

No credentials sent to the network and no Docker actions.
"""
from pathlib import Path
import json
import stat
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))
from app.config import settings
from app.signed_node_origins import (
    approved_node, control_url_matches, ApprovedOriginUnavailable,
)
from app.uopti_backhaul_lifecycle import review_backhaul_edit
from app.uopti_backhaul_standard import StandardBackhaulSpecError
from app.node_client import NodeClient


NODE = "bbbbbbbb-1111-2222-3333-444444444444"
BASE_SPEC = {
    "uopti_standard_backhaul": True, "token": "TEST-ONLY-NOT-A-REAL-TOKEN-12345",
    "type": "ws", "transport": "ws",
    "ports": ["127.0.0.1:56053=127.0.0.1:56053"],
    "data_port": 56053, "control_port": 3080, "bridge_port": 13080,
}


class ApprovedNodeOriginsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        parent = Path(self.tmp.name) / "approved"
        parent.mkdir(mode=0o700)
        self.file = parent / "nodes.json"
        self.write({
            NODE: {"role": "foreign", "node_name": "kh-node",
                   "origin": "https://kh.example.org:443",
                   "control_url": "https://kh.example.org/hidden/control/"}
        })
        self.previous = settings.smite_signed_node_origins_path
        settings.smite_signed_node_origins_path = str(self.file)
        self.addCleanup(setattr, settings, "smite_signed_node_origins_path", self.previous)

    def write(self, nodes):
        self.file.write_text(json.dumps({"version": 1, "nodes": nodes}))
        self.file.chmod(0o600)

    def test_approved_origin_trumps_legacy_metadata(self):
        result = approved_node(NODE)
        self.assertEqual(result["origin"], "https://kh.example.org:443")
        self.assertEqual(result["role"], "foreign")
        self.assertTrue(control_url_matches(
            result, "https://kh.example.org/hidden/control/"
        ))
        self.assertTrue(control_url_matches(
            result, "https://kh.example.org:443/hidden/control"
        ))
        self.assertFalse(control_url_matches(
            result, "https://attacker.example.org/hidden/control/"
        ))
        self.assertFalse(control_url_matches(
            result, "http://kh.example.org/hidden/control/"
        ))
        self.assertFalse(control_url_matches(
            result, "https://kh.example.org/hidden/../control/"
        ))

    def test_missing_revoked_untrusted_file_denied(self):
        with self.assertRaises(ApprovedOriginUnavailable):
            approved_node("node-that-was-not-approved")
        self.file.chmod(0o644)
        with self.assertRaises(ApprovedOriginUnavailable):
            approved_node(NODE)
        self.file.chmod(0o600)
        self.file.parent.chmod(0o755)
        with self.assertRaises(ApprovedOriginUnavailable):
            approved_node(NODE)
        self.file.parent.chmod(0o700)
        self.file.unlink()
        self.file.symlink_to(Path(self.tmp.name) / "missing")
        with self.assertRaises(ApprovedOriginUnavailable):
            approved_node(NODE)

    def test_unapproved_off_machine_plaintext_or_ip_denied(self):
        for origin in (
            "http://kh.example.org:8888", "http://127.0.0.1:8888",
            "https://91.107.185.50:443", "https://kh.example.org:8443",
            "https://name:password@kh.example.org:443",
            "https://kh.example.org:443/target",
            "https://kh.example.org:443?foo=1",
        ):
            with self.subTest(origin=origin):
                self.write({NODE: {
                    "role": "foreign", "node_name": "kh-node",
                    "origin": origin,
                    "control_url": "https://kh.example.org/hidden/control",
                }})
                with self.assertRaises(ApprovedOriginUnavailable):
                    approved_node(NODE)

    def test_explicit_local_iran_node_only(self):
        self.write({NODE: {
            "role": "iran", "node_name": "ir-node",
            "origin": "http://127.0.0.1:8888",
            "control_url": "http://127.0.0.1:8888/control/local/",
        }})
        self.assertEqual(approved_node(NODE)["origin"], "http://127.0.0.1:8888")

    def test_standard_backhaul_edits_preflight_before_write(self):
        self.assertTrue(review_backhaul_edit(
            core="backhaul", old_spec=BASE_SPEC, proposed_spec=dict(BASE_SPEC)
        ))
        with self.assertRaises(StandardBackhaulSpecError):
            review_backhaul_edit(core="backhaul", old_spec=BASE_SPEC,
                                 proposed_spec={"type": "ws"})
        with self.assertRaises(StandardBackhaulSpecError):
            review_backhaul_edit(core="backhaul", old_spec=BASE_SPEC,
                                 proposed_spec=dict(BASE_SPEC, bind_ip="0.0.0.0"))
        self.assertFalse(review_backhaul_edit(
            core="frp", old_spec={}, proposed_spec={"port": 7000}
        ))
        self.assertFalse(review_backhaul_edit(
            core="backhaul", old_spec={"type": "tcp"},
            proposed_spec={"type": "tcp"}
        ))

    def test_source_invariants_signed_routing_and_no_panel_duplicate(self):
        node_source = (ROOT / "panel/app/node_client.py").read_text()
        signed_section = node_source.split("async def _signed_agent_request(", 1)[1].split(
            "\n    async def send_to_node", 1
        )[0]
        self.assertIn("pin = approved_node(node_id)", signed_section)
        self.assertIn('address, using_frp = pin["origin"], False', signed_section)
        self.assertNotIn("await self._get_node_address(node)", signed_section)

        tunnel_source = (ROOT / "panel/app/routers/tunnels.py").read_text()
        update = tunnel_source.split("async def update_tunnel(", 1)[1].split(
            '@router.post("/{tunnel_id}/apply")', 1
        )[0]
        self.assertLess(
            update.index("review_backhaul_edit("),
            update.index("await db.commit()")
        )
        self.assertIn('and not standard_backhaul', update)


if __name__ == "__main__":
    unittest.main()
