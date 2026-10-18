"""Stage 11: offline Standard Backhaul + FRP/443 integration regression tests.

No Docker, tunnels, network or live service modification.
"""
import asyncio
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))
from app.uopti_backhaul_dispatch import compile_dispatch_payload
from app.uopti_backhaul_standard import (
    compile_standard_specs, normalize_node_spec, StandardBackhaulSpecError,
)
from app.node_client import NodeClient
from app.config import settings as panel_settings

NODE_MODULE = ROOT / "node/app/uopti_backhaul_standard.py"
FRP_HELPER = ROOT / "node/app/frp_gateway_config.py"


def isolated(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


node_backhaul = isolated(NODE_MODULE, "node_backhaul_spec")
frp = isolated(FRP_HELPER, "frp_gateway_config_stage11")

CANONICAL = {
    "uopti_standard_backhaul": True,
    "token": "EXAMPLE-UNIT-TEST-TOKEN-12345678901234",
    "transport": "ws",
    "type": "ws",
    "ports": ["127.0.0.1:56053=127.0.0.1:56053"],
    "data_port": 56053,
    "control_port": 3080,
    "bridge_port": 13080,
}


class BackhaulSignedDispatchTest(unittest.IsolatedAsyncioTestCase):
    def test_compilers_are_identical_and_preserve_loopback(self):
        self.assertEqual(
            (ROOT / "panel/app/uopti_backhaul_standard.py").read_bytes(),
            NODE_MODULE.read_bytes(),
        )
        server, client = compile_standard_specs(CANONICAL)
        self.assertEqual(server["mode"], "server")
        self.assertEqual(client["mode"], "client")
        self.assertEqual(server["bind_addr"], "127.0.0.1:3080")
        self.assertEqual(client["remote_addr"], "127.0.0.1:13080")
        self.assertEqual(server["ports"], ["127.0.0.1:56053=127.0.0.1:56053"])
        self.assertEqual(node_backhaul.normalize_node_spec(server), server)
        self.assertEqual(node_backhaul.normalize_node_spec(client), client)

    def test_signed_and_legacy_dispatch_prepare_same_persisted_spec(self):
        original = {
            "tunnel_id": "tunnel-01", "core": "backhaul",
            "type": "ws", "spec": {"token": "IGNORED-ATTACKER-VALUE"}
        }
        iran = compile_dispatch_payload(
            node_role="iran", stored_spec=CANONICAL,
            endpoint="/api/agent/tunnels/apply", incoming=original,
        )
        foreign = compile_dispatch_payload(
            node_role="foreign", stored_spec=CANONICAL,
            endpoint="/api/agent/tunnels/apply", incoming=original,
        )
        self.assertEqual(iran["spec"]["mode"], "server")
        self.assertEqual(foreign["spec"]["mode"], "client")
        self.assertEqual(iran["spec"]["token"], CANONICAL["token"])
        self.assertEqual(original["spec"]["token"], "IGNORED-ATTACKER-VALUE")
        self.assertEqual(foreign["spec"]["remote_addr"], "127.0.0.1:13080")

    def test_flag_requires_persisted_approval_and_valid_role(self):
        request = {
            "core": "backhaul", "spec": {"uopti_standard_backhaul": True},
        }
        with self.assertRaises(StandardBackhaulSpecError):
            compile_dispatch_payload(
                node_role="foreign", stored_spec={},
                endpoint="/api/agent/tunnels/apply", incoming=request,
            )
        with self.assertRaises(StandardBackhaulSpecError):
            compile_dispatch_payload(
                node_role="unknown", stored_spec=CANONICAL,
                endpoint="/api/agent/tunnels/apply", incoming=request,
            )
        bad = dict(CANONICAL, bind_ip="0.0.0.0")
        with self.assertRaises(StandardBackhaulSpecError):
            compile_dispatch_payload(
                node_role="iran", stored_spec=bad,
                endpoint="/api/agent/tunnels/apply", incoming=request,
            )

    def test_frp_and_regular_backhaul_passthrough(self):
        request = {"core": "frp", "spec": {"client": True}}
        self.assertIs(
            compile_dispatch_payload(
                node_role=None, stored_spec=None,
                endpoint="/api/agent/tunnels/apply", incoming=request,
            ), request
        )
        existing = {"core": "backhaul", "spec": {"transport": "tcp"}}
        self.assertIs(
            compile_dispatch_payload(
                node_role="iran", stored_spec={},
                endpoint="/api/agent/tunnels/apply", incoming=existing,
            ), existing
        )

    async def test_actual_nodeclient_signed_path_receives_normalized_payload(self):
        client = NodeClient()
        original = panel_settings.smite_panel_agent_auth_mode
        panel_settings.smite_panel_agent_auth_mode = "signed"
        self.addCleanup(setattr, panel_settings, "smite_panel_agent_auth_mode", original)
        standardized = {
            "core": "backhaul", "tunnel_id": "t1",
            "spec": {"mode": "client", "uopti_standard_backhaul": True}
        }
        with patch("app.node_client.prepare_node_command",
                   new_callable=AsyncMock, return_value=standardized) as prepare:
            with patch.object(client, "_signed_agent_request",
                              new_callable=AsyncMock, return_value={"status": "ok"}) as signed:
                result = await client.send_to_node(
                    "node-abcd1234", "/api/agent/tunnels/apply",
                    {"core": "backhaul", "tunnel_id": "t1", "spec": {}},
                )
                self.assertEqual(result, {"status": "ok"})
                prepare.assert_awaited_once()
                self.assertEqual(
                    signed.await_args.kwargs["payload"], standardized
                )

    async def test_invalid_standard_never_calls_signed_transport(self):
        client = NodeClient()
        original = panel_settings.smite_panel_agent_auth_mode
        panel_settings.smite_panel_agent_auth_mode = "signed"
        self.addCleanup(setattr, panel_settings, "smite_panel_agent_auth_mode", original)
        with patch("app.node_client.prepare_node_command",
                   new_callable=AsyncMock, side_effect=StandardBackhaulSpecError("bad")):
            with patch.object(client, "_signed_agent_request", new_callable=AsyncMock) as signed:
                reply = await client.send_to_node(
                    "node-abcd1234", "/api/agent/tunnels/apply",
                    {"core": "backhaul", "spec": {}},
                )
                self.assertEqual(reply["status"], "error")
                signed.assert_not_awaited()


class FrpStandardWssTest(unittest.TestCase):
    def test_default_off_does_not_force_tcp_frp_to_wss(self):
        with patch.dict(os.environ, {"PANEL_ADDRESS": "panel.example.org:443",
                                     "SMITE_FRP_STANDARD_WSS": "0"}):
            self.assertEqual(frp.frp_standard_wss_host(), "")
            self.assertEqual(frp.frp_client_server_port({}, 7000), 7000)
            self.assertEqual(frp.frp_tls_transport_yaml({}), "")

    def test_explicit_wss_443_uses_existing_domain(self):
        with patch.dict(os.environ, {"PANEL_ADDRESS": "panel.example.org:443",
                                     "SMITE_FRP_STANDARD_WSS": "1"}):
            self.assertEqual(frp.frp_standard_wss_host(), "panel.example.org")
            self.assertEqual(frp.frp_client_server_addr("127.0.0.1"), "panel.example.org")
            self.assertEqual(frp.frp_client_server_port({}, 7000), 443)
            self.assertIn("protocol: wss", frp.frp_tls_transport_yaml({}))
            with self.assertRaises(ValueError):
                frp.frp_client_server_port({"frp_gateway_port": 8443}, 7000)
            with self.assertRaises(ValueError):
                frp.frp_tls_transport_yaml({"frp_tls_server_name": "evil.example.org"})

    def test_updated_adapter_contains_opt_in_frp_and_pre_stop_backhaul_guard(self):
        text = (ROOT / "node/app/core_adapters.py").read_text()
        self.assertIn("server_port = frp_client_server_port", text)
        self.assertIn("frp_standard_wss_host()", text)
        self.assertIn("normalize_node_spec(spec)", text)
        self.assertLess(
            text.index("spec = normalize_node_spec(spec)"),
            text.index("if tunnel_id in self.processes:", text.index("class BackhaulAdapter:")),
        )
        self.assertIn('if spec.get("uopti_standard_backhaul") is True:', text)
        self.assertIn('os.fchmod(cfg.fileno(), 0o600)', text)
        self.assertIn('if spec.get("uopti_standard_backhaul") is not True:', text)


if __name__ == "__main__":
    unittest.main()
