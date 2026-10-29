import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'panel'))
from app import frp_wss_panel as policy

class WssPanel(unittest.TestCase):
    def setUp(self):
        self.s = SimpleNamespace(smite_frp_standard_wss=True, panel_domain='ir.example.net',
            smite_panel_agent_auth_mode='signed', smite_engine_management_mode='managed')
        p = patch.object(policy, 'settings', self.s); p.start(); self.addCleanup(p.stop)
    def test_ipless_signed_owner_uses_configured_domain(self):
        self.assertEqual(policy.server_address(SimpleNamespace(node_metadata={})), 'ir.example.net')
        self.assertEqual(policy.owner_spec({}, 'tcp'), {'bind_port':7000,'local_ip':'127.0.0.1'})
    def test_fail_closed(self):
        for bad in ({'bind_port':8000}, {'local_ip':'0.0.0.0'}, {'frp_gateway_port':7000}, {'frp_tls_server_name':'evil.example'}):
            with self.assertRaises(ValueError): policy.owner_spec(bad, 'tcp')
        with self.assertRaises(ValueError): policy.owner_spec({}, 'udp')
        self.s.smite_panel_agent_auth_mode='legacy'
        with self.assertRaises(ValueError): policy.owner_spec({}, 'tcp')
    def test_bad_domain_and_disabled_mode(self):
        self.s.panel_domain='ir.example.net;\ninclude evil;'
        with self.assertRaises(ValueError): policy.wss_host()
        self.s.smite_frp_standard_wss=False
        self.assertEqual(policy.owner_spec({'bind_port':9000}, 'udp'), {'bind_port':9000})

if __name__ == '__main__': unittest.main()
