"""Offline runtime-backed Node attestation contract: no FRP/Sanaei writes."""
import importlib.util
import pathlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("node_runtime_proof",ROOT/"node/app/approval_runtime_evidence.py")
proof=importlib.util.module_from_spec(spec);sys.modules[spec.name]=proof
spec.loader.exec_module(proof)

class ProofTests(unittest.TestCase):
    def setUp(self):
        self.called=[]
        auth=types.ModuleType("app.agent_auth")
        auth.read_identity=lambda path:("node-ir-0001",b"old-pairing-unchanged")
        owner=types.ModuleType("app.frp_owner_status")
        owner.active_signed_frps_owners=lambda manager:[{
            "tunnel_id":"owner-0001","control_port":7000,"proxy_ports":[45121,38658,28897]}]
        sanaei=types.ModuleType("app.sanaei_inbound_inventory")
        sanaei.list_approved_xhttp_inbounds=lambda path:[{
            "port":45121,"path":"/45121/www","listen":"127.0.0.1",
            "protocol":"vless","network":"xhttp","enabled":True}]
        attest=types.ModuleType("app.approval_attestation")
        def signer(**kw):
            self.called.append(kw)
            return {"signed":"NODE_KEY"}
        attest.attest=signer
        self.modules={"app.agent_auth":auth,"app.frp_owner_status":owner,
                      "app.sanaei_inbound_inventory":sanaei,"app.approval_attestation":attest}
        mock=patch.dict(sys.modules,self.modules)
        mock.start();self.addCleanup(mock.stop)
        p=patch.dict("os.environ",{"SMITE_STAGE15_APPROVAL_ATTESTATION_KEY":"/root/pinned-node-key"})
        p.start();self.addCleanup(p.stop)
        self.settings=SimpleNamespace(
            smite_agent_auth_mode="strict",node_role="iran",
            smite_agent_identity_path="/private/current",
            smite_sanaei_inventory_enabled=True,
            smite_sanaei_db_path="/trusted/x-ui.db")

    def test_real_runtime_owner_port_signed_from_live_inventory(self):
        result=proof.collect(kind="frps_owner",port=38658,
             settings=self.settings,adapter_manager=object(),now=1000)
        self.assertEqual(result,{"signed":"NODE_KEY"})
        self.assertEqual(self.called[0]["facts"],{
             "tunnel_id":"owner-0001","control_port":7000,"proxy_port":38658})

    def test_kh_inbound_from_local_read_only_sanaei(self):
        self.settings.node_role="foreign"
        proof.collect(kind="xhttp_inbound",port=45121,settings=self.settings,now=1000)
        self.assertEqual(self.called[0]["facts"]["path"],"/45121/www")

    def test_no_local_matching_inbound_holds(self):
        self.settings.node_role="foreign"
        with self.assertRaises(proof.RuntimeAttestationHold):
            proof.collect(kind="xhttp_inbound",port=38658,settings=self.settings)
        self.assertEqual(self.called,[])

    def test_wrong_role_holds(self):
        self.settings.node_role="foreign"
        with self.assertRaises(proof.RuntimeAttestationHold):
            proof.collect(kind="frps_owner",port=38658,settings=self.settings,adapter_manager=object())

    def test_default_off_no_key(self):
        import os
        with patch.dict(os.environ,{"SMITE_STAGE15_APPROVAL_ATTESTATION_KEY":""}):
            with self.assertRaises(proof.RuntimeAttestationHold):
                proof.collect(kind="frps_owner",port=38658,
                              settings=self.settings,adapter_manager=object())

    def test_reject_frps_control_port(self):
        with self.assertRaises(proof.RuntimeAttestationHold):
            proof.collect(kind="frps_owner",port=7000,
                          settings=self.settings,adapter_manager=object())

if __name__=="__main__":
    unittest.main()
