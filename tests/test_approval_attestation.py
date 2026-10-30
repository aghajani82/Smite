"""Offline attestation source: payload signature and fail-closed contracts."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

module = Path(__file__).resolve().parents[1] / "node/app/approval_attestation.py"
spec = importlib.util.spec_from_file_location("independent_approval_attestation", module)
att = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = att
spec.loader.exec_module(att)


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate()
        self.facts={"tunnel_id":"owner-0001","control_port":7000,"proxy_port":45121}

    def sign(self, kind="frps_owner", facts=None):
        with patch.object(att,"_private_key",return_value=self.key):
            return att.attest(kind=kind,node_id="node-ir-0001",
                facts=self.facts if facts is None else facts,
                nonce="a"*32,key_path=Path("/nonexistent"),now=1000)

    def test_signature_and_expiration(self):
        value=self.sign()
        sig=base64.urlsafe_b64decode(value["signature"]+"==")
        body={k:v for k,v in value.items() if k!="signature"}
        self.key.public_key().verify(sig,att.canonical(body))
        self.assertEqual(value["expires_at"]-value["issued_at"],30)

    def test_tamper_fails_cryptographic_verification(self):
        value=self.sign();value["facts"]["proxy_port"]=38658
        from cryptography.exceptions import InvalidSignature
        with self.assertRaises(InvalidSignature):
            self.key.public_key().verify(base64.urlsafe_b64decode(value["signature"]+"=="),
                att.canonical({k:v for k,v in value.items() if k!="signature"}))

    def test_owner_invalid_port(self):
        with self.assertRaises(att.AttestationHold):
            self.sign(facts={"tunnel_id":"owner-0001","control_port":7000,"proxy_port":7000})

    def test_lease_direct_and_shared(self):
        facts={"ir_node":"node-ir-0001","kh_node":"node-kh-0001",
            "owner":"owner-0001","child":"owner-0001","lease":"owner-0001",
            "port":45121,"role":"direct","state":"active","unique":True,
            "owner_count":1,"proxy_port_count":1}
        self.sign("active_lease",facts)
        facts.update(child="child-0001",lease="child-0001",role="shared")
        self.sign("active_lease",facts)
        facts["unique"]=False
        with self.assertRaises(att.AttestationHold):
            self.sign("active_lease",facts)

    def test_missing_signed_runtime_cannot_issue(self):
        with self.assertRaises(att.AttestationHold): self.sign("active_lease",{})
        with self.assertRaises(att.AttestationHold): self.sign("xhttp_inbound",{})

    def test_inbound(self):
        facts={"port":45121,"listen":"127.0.0.1","protocol":"vless",
            "network":"xhttp","path":"/45121/www","enabled":True}
        self.sign("xhttp_inbound",facts)
        facts["listen"]="0.0.0.0"
        with self.assertRaises(att.AttestationHold): self.sign("xhttp_inbound",facts)

if __name__=="__main__":
    unittest.main()
