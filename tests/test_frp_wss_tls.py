import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('frp_tls', Path(__file__).resolve().parents[1]/'node/app/frp_gateway_config.py')
gateway = importlib.util.module_from_spec(spec); spec.loader.exec_module(gateway)
class WssTLS(unittest.TestCase):
    def test_wss_uses_ca_bundle_and_pinned_hostname(self):
        with patch.dict(os.environ, {'SMITE_FRP_STANDARD_WSS':'1','PANEL_ADDRESS':'ir.example.net:443'}, clear=True):
            text = gateway.frp_tls_transport_yaml({})
            self.assertIn('trustedCaFile: "/etc/ssl/certs/ca-certificates.crt"', text)
            self.assertIn('serverName: "ir.example.net"', text)
            with self.assertRaises(ValueError): gateway.frp_tls_transport_yaml({'frp_tls_server_name':'evil.example'})
    def test_no_implicit_activation(self):
        with patch.dict(os.environ, {}, clear=True): self.assertEqual(gateway.frp_tls_transport_yaml({}), '')
if __name__=='__main__': unittest.main()
