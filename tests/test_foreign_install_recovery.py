"""Real HMAC + durable replay + grant evidence, no runtime activation."""
import json
from pathlib import Path
import sys
import sqlite3
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'panel'))
import test_foreign_install_grants as fixture
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.config import settings
from app import node_auth, signed_node_registration
from app.routers import signed_nodes

class Recovery(unittest.TestCase):
    issue=fixture.Grants.issue
    redeem=fixture.Grants.redeem
    def setUp(self):
        fixture.Grants.setUp(self)
        self.now=int(time.time())-10000
        self.grant=self.issue();self.redeem(self.grant)
        signed_node_registration.initialize_replay_schema(self.db)
        parent=Path(self.tmp.name)/'trust';parent.mkdir(mode=0o700)
        for key,value in dict(db_path=str(self.db),db_type='sqlite',smite_node_pairing_master_key=self.master.decode(),
                smite_node_registration_mode='signed',smite_panel_agent_auth_mode='signed',
                smite_foreign_install_origin_trust_enabled=True,smite_foreign_install_enabled=False,
                smite_signed_node_origins_path=str(parent/'origins.json')).items():
            previous=getattr(settings,key);setattr(settings,key,value);self.addCleanup(setattr,settings,key,previous)
        app=FastAPI();app.include_router(signed_nodes.router,prefix='/api/node-control')
        self.client=TestClient(app);self.addCleanup(self.client.close)
    def request(self,secret=None,body=None,headers=None):
        body=json.dumps({'node_id':self.node}).encode() if body is None else body
        headers=node_auth.sign_request(secret=(secret or self.secret).encode(),node_id=self.node,method='POST',
            target='/api/node-control/installation-status',body=body) if headers is None else headers
        return self.client.post('/api/node-control/installation-status',content=body,headers=headers)
    def test_expired_grant_and_disabled_issuance_allow_proof_without_activation(self):
        result=self.request();self.assertEqual(result.status_code,200)
        self.assertEqual(result.json(),dict(status='enrolled',node_id=self.node,node_name='node-kh',origin=self.grant.origin,control_url=self.grant.control_url))
        self.assertEqual(result.headers['cache-control'],'no-store')
        self.assertNotIn(self.secret,result.text)
        with sqlite3.connect(self.db) as db:
            meta=json.loads(db.execute('SELECT metadata FROM nodes').fetchone()[0])
        self.assertEqual(meta['provisioning'],'reserved_for_pairing')
    def test_wrong_secret_and_unsigned_denied(self):
        self.assertEqual(self.request(secret='f'*64).status_code,401)
        self.assertEqual(self.request(headers={}).status_code,401)
    def test_replay_denied(self):
        body=json.dumps({'node_id':self.node}).encode()
        headers=node_auth.sign_request(secret=self.secret.encode(),node_id=self.node,method='POST',target='/api/node-control/installation-status',body=body)
        self.assertEqual(self.request(body=body,headers=headers).status_code,200)
        self.assertEqual(self.request(body=body,headers=headers).status_code,401)
    def test_revoked_identity_denied(self):
        with sqlite3.connect(self.db) as db:db.execute('UPDATE smite_node_identities SET revoked_at=1')
        self.assertEqual(self.request().status_code,401)
    def test_wrong_scope_or_disabled_trust_denied(self):
        self.assertEqual(self.request(body=b'{"node_id":"another-node"}').status_code,403)
        settings.smite_foreign_install_origin_trust_enabled=False
        self.assertEqual(self.request().status_code,503)
    def test_missing_origin_evidence_denied(self):
        with sqlite3.connect(self.db) as db:db.execute('DELETE FROM smite_foreign_install_origins')
        self.assertEqual(self.request().status_code,403)

if __name__=='__main__':unittest.main()
