"""Offline regression tests for optional FRPC TLS/SNI gateway support.

Run: python3 -m unittest discover -s tests -p 'test_frp_gateway.py' -v
"""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "node"))

from app.frp_gateway_config import frp_client_server_port, frp_tls_transport_yaml


def panel_port_helper():
    """Load only the pure port helper, without importing panel service dependencies."""
    filename = ROOT / "panel" / "app" / "routers" / "tunnels.py"
    source = ast.parse(filename.read_text(), filename=str(filename))
    target = next(
        node for node in source.body
        if isinstance(node, ast.FunctionDef) and node.name == "frp_client_gateway_port"
    )
    module = ast.Module(body=[target], type_ignores=[])
    context = {}
    exec(compile(module, str(filename), "exec"), context)
    return context["frp_client_gateway_port"]


class FrpGatewayConfigTest(unittest.TestCase):
    def test_legacy_configs_remain_unchanged(self):
        self.assertEqual(frp_client_server_port({}, 17000), 17000)
        self.assertEqual(frp_tls_transport_yaml({}), "")
        self.assertEqual(panel_port_helper()({}, 17000), 17000)

    def test_gateway_443_and_sni(self):
        spec = {
            "frp_gateway_port": 443,
            "frp_tls_server_name": "frp-file.ir.kolbe1.ir",
        }
        self.assertEqual(frp_client_server_port(spec, 17000), 443)
        self.assertEqual(panel_port_helper()(spec, 17000), 443)
        rendered = frp_tls_transport_yaml(spec)
        self.assertIn('serverName: "frp-file.ir.kolbe1.ir"', rendered)
        self.assertIn("disableCustomTLSFirstByte: true", rendered)
        self.assertIn("enable: true", rendered)

    def test_gateway_port_needs_sni(self):
        spec = {"frp_gateway_port": 443}
        with self.assertRaises(ValueError):
            frp_client_server_port(spec, 17000)
        with self.assertRaises(ValueError):
            frp_tls_transport_yaml(spec)
        with self.assertRaises(ValueError):
            panel_port_helper()(spec, 17000)

    def test_reject_invalid_gateway_ports(self):
        for raw in (0, 65536, -1, "443abc", True, "0", "65536", "443\n"):
            with self.subTest(raw=raw):
                spec = {"frp_gateway_port": raw, "frp_tls_server_name": "frp.example.org"}
                with self.assertRaises(ValueError):
                    frp_client_server_port(spec, 17000)
                with self.assertRaises(ValueError):
                    panel_port_helper()(spec, 17000)

    def test_reject_sni_yaml_injection(self):
        for sni in ('frp.example.org"\nauth: none', "http://frp.example.org", "bad..example.org", "localhost", "foo_bar.example.org", 4):
            with self.subTest(sni=sni):
                with self.assertRaises(ValueError):
                    frp_tls_transport_yaml({"frp_tls_server_name": sni})

    def test_panel_restart_respects_gateway_port(self):
        """Panel startup synchronization must not reset FRPC back to bindPort."""
        path = ROOT / "panel" / "main.py"
        parsed = ast.parse(path.read_text(), filename=str(path))
        method = next(
            node for node in parsed.body
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "_restore_node_tunnels"
        )
        matches = [
            node for node in ast.walk(method)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Subscript)
                and isinstance(t.value, ast.Name)
                and t.value.id == "client_spec"
                and isinstance(t.slice, ast.Constant)
                and t.slice.value == "server_port"
                for t in node.targets
            )
        ]
        self.assertEqual(len(matches), 1)
        value = matches[0].value
        self.assertIsInstance(value, ast.Call)
        self.assertIsInstance(value.func, ast.Attribute)
        self.assertEqual(value.func.attr, "frp_client_gateway_port")
        self.assertIsInstance(value.func.value, ast.Name)
        self.assertEqual(value.func.value.id, "tunnels")

    def test_sni_without_gateway_port_preserves_control_port(self):
        spec = {"frp_tls_server_name": "frp-file.ir.kolbe1.ir"}
        self.assertEqual(frp_client_server_port(spec, 17000), 17000)
        self.assertIn("serverName:", frp_tls_transport_yaml(spec))


if __name__ == "__main__":
    unittest.main()
