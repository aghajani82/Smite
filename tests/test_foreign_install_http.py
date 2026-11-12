"""Actual JWT/MFA dependencies + isolated ASGI/SQLite; no production startup."""
import ast
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'panel'))
from app.config import settings
from app.database import get_db
from app.routers import foreign_install as api, auth
from app import foreign_install_grants as grants, node_pairing_store as pairing


class ForeignInstallHTTP(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'panel.db'
        self.node = 'foreign-node-1234'
        self.secret = secrets.token_hex(32)
        self.ingress = secrets.token_hex(32)
        values = dict(db_path=str(self.db), smite_foreign_install_enabled=True,
            smite_node_pairing_preview_enabled=True,
            smite_node_pairing_master_key=Fernet.generate_key().decode(),
            smite_node_pairing_ingress_token=self.ingress,
            smite_node_registration_mode='signed',smite_panel_agent_auth_mode='signed')
        self.previous = {key:getattr(settings,key) for key in values}
        for key,value in values.items(): setattr(settings,key,value)
        self.addCleanup(lambda: [setattr(settings,k,v) for k,v in self.previous.items()])
        with sqlite3.connect(self.db) as c:
            c.execute('CREATE TABLE nodes (id TEXT PRIMARY KEY,name TEXT,metadata TEXT)')
            c.execute('INSERT INTO nodes VALUES (?,?,?)', (self.node,'node-kh',json.dumps({'role':'foreign','provisioning':'reserved_for_pairing'})))
        pairing.initialize_schema(self.db)
        grants.initialize_schema(self.db)
        self.user = SimpleNamespace(id='admin-1234', username='admin',auth_version=7,totp_secret='enabled')
        user = self.user
        class AdminDB:
            async def execute(self, _):
                return SimpleNamespace(scalar_one_or_none=lambda: user)
        async def admin_db(): yield AdminDB()
        app = FastAPI()
        app.include_router(api.router,prefix='/api/foreign-install')
        app.dependency_overrides[get_db] = admin_db
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.headers = self.jwt(mfa=True, version=7)

    def jwt(self,mfa=True,version=7):
        return {'Authorization':'Bearer '+auth.create_access_token({'sub':'admin','mfa':mfa,'v':version})}

    def issue(self,headers=None,**kw):
        body=dict(node_id=self.node,node_name='node-kh',domain='kh.example.com')
        body.update(kw)
        return self.client.post('/api/foreign-install/issue',json=body,headers=self.headers if headers is None else headers)

    def redeem(self,grant,headers=None,**kw):
        body=dict(node_id=self.node,node_name='node-kh',control_url=grant['control_url'],installation_code=grant['installation_code'],node_secret=self.secret)
        body.update(kw)
        return self.client.post('/api/foreign-install/redeem',json=body,headers={'X-Smite-Pairing-Ingress':self.ingress} if headers is None else headers)

    def private(self,response):
        self.assertEqual(response.headers.get('cache-control'),'no-store')
        self.assertEqual(response.headers.get('referrer-policy'),'no-referrer')
        self.assertNotIn(self.secret,response.text)

    def test_actual_admin_jwt_mfa_and_version_required(self):
        for headers in ({},{'Authorization':'Bearer invalid'},self.jwt(mfa=False),self.jwt(version=6)):
            for method,path,body in [('GET','capabilities',None),('POST','issue',dict(node_id=self.node,node_name='node-kh',domain='kh.example.com')),('POST','revoke',{'node_id':self.node})]:
                with self.subTest(path=path,headers=bool(headers)):
                    r=self.client.request(method,'/api/foreign-install/'+path,json=body,headers=headers)
                    self.assertIn(r.status_code,(401,403))
                    self.private(r)
        self.assertEqual(self.issue().status_code,200)

    def test_disabled_flag_and_signed_mode_gates(self):
        for key,value in [('smite_foreign_install_enabled',False),('smite_node_pairing_preview_enabled',False),('smite_node_registration_mode','legacy'),('smite_panel_agent_auth_mode','legacy'),('smite_node_pairing_master_key','invalid')]:
            old=getattr(settings,key)
            try:
                setattr(settings,key,value)
                r=self.issue(); self.assertEqual(r.status_code,503); self.private(r)
                cap=self.client.get('/api/foreign-install/capabilities',headers=self.headers)
                self.assertFalse(cap.json()['foreign_install_enabled'])
            finally: setattr(settings,key,old)

    def test_capabilities_and_no_automatic_migration(self):
        r=self.client.get('/api/foreign-install/capabilities',headers=self.headers)
        self.assertEqual(r.json(),{'foreign_install_enabled':True,'default_ttl_seconds':7200,'max_ttl_seconds':7200,'protocol':'smi1'})
        self.private(r)
        with sqlite3.connect(self.db) as c: c.execute('DROP TABLE smite_foreign_install_origins')
        self.assertEqual(self.issue().status_code,503)
        with sqlite3.connect(self.db) as c:
            self.assertIsNone(c.execute("SELECT name FROM sqlite_master WHERE name='smite_foreign_install_origins'").fetchone())

    def test_missing_db_not_created(self):
        missing=Path(self.tmp.name)/'missing.db'
        settings.db_path=str(missing)
        self.assertEqual(self.issue().status_code,503)
        self.assertFalse(missing.exists())

    def test_symlink_db_refused(self):
        link=Path(self.tmp.name)/'link.db'; link.symlink_to(self.db)
        settings.db_path=str(link)
        self.assertEqual(self.issue().status_code,503)

    def test_real_issue_ingress_redemption_and_retry(self):
        issued=self.issue(); self.assertEqual(issued.status_code,200)
        self.private(issued)
        grant=issued.json()
        for headers in ({},{'X-Forwarded-Proto':'https'},{'X-Smite-Pairing-Ingress':'fake'},self.headers):
            r=self.redeem(grant,headers=headers); self.assertEqual(r.status_code,403); self.private(r)
        for _ in range(2):
            r=self.redeem(grant); self.assertEqual(r.status_code,200,r.text)
            self.assertEqual(r.json(),{'status':'enrolled','node_id':self.node}); self.private(r)
            self.assertNotIn(grant['installation_code'],r.text)
        self.assertEqual(pairing.get_active_secret(self.db,master_key=settings.smite_node_pairing_master_key,node_id=self.node),self.secret.encode())
        self.assertEqual(self.redeem(grant,node_secret=secrets.token_hex(32)).status_code,403)

    def test_untrusted_scope_and_unknown_fields_rejected(self):
        grant=self.issue().json()
        for change in ({'node_name':'wrong'},{'control_url':'https://evil.example.com:443/path'},{'node_id':'different-node'}):
            r=self.redeem(grant,**change);self.assertEqual(r.status_code,403); self.private(r)
        self.assertEqual(self.issue(role='iran').status_code,422)
        self.assertEqual(self.issue(domain='http://127.0.0.1').status_code,409)

    def test_invalid_credentials_never_reflected(self):
        grant=self.issue().json()
        for change in ({'installation_code':grant['installation_code']+'!'},{'node_secret':self.secret+'!'},{'node_secret':{'secret':self.secret}},{'extra':self.secret}):
            r=self.redeem(grant,**change); self.assertEqual(r.status_code,422); self.private(r)
            self.assertNotIn(grant['installation_code'],r.text)

    def test_malformed_json_and_oversized_stream(self):
        for data,status in [(b'{"secret":"'+self.secret.encode()+b'"',422),(b'x'*8193,413)]:
            r=self.client.post('/api/foreign-install/redeem',content=data,headers={'Content-Type':'application/json'})
            self.assertEqual(r.status_code,status); self.private(r)
        r=self.client.post('/api/foreign-install/redeem',content=iter([b'x'*4096,b'x'*4097]))
        self.assertEqual(r.status_code,413); self.private(r)

    def test_pending_revocation(self):
        grant=self.issue().json()
        r=self.client.post('/api/foreign-install/revoke',json={'node_id':self.node},headers=self.headers)
        self.assertEqual(r.status_code,200);self.private(r)
        self.assertEqual(self.redeem(grant).status_code,403)

    def test_sql_error_sanitized(self):
        with patch.object(grants,'issue',side_effect=sqlite3.OperationalError(self.secret)):
            r=self.issue();self.assertEqual(r.status_code,503);self.private(r)

    def test_ttl_strict_types(self):
        for ttl in (True,'7200',7201,59): self.assertEqual(self.issue(ttl_seconds=ttl).status_code,422)

    def test_router_mounted_and_flag_default_false(self):
        from app.config import Settings
        self.assertFalse(Settings.model_fields['smite_foreign_install_enabled'].default)
        tree=ast.parse((ROOT/'panel/main.py').read_text())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='include_router' and n.args and ast.unparse(n.args[0])=='foreign_install.router']
        self.assertEqual(len(calls),1)
        self.assertEqual(next(k.value.value for k in calls[0].keywords if k.arg=='prefix'),'/api/foreign-install')


if __name__=='__main__': unittest.main()
