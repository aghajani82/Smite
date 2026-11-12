"""Offline SQLite tests; no service, network or host configuration touched."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
import unittest
from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'panel'))
from app import foreign_install_grants as g
from app import node_pairing_store as p


class Grants(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'panel.db'
        self.master = Fernet.generate_key()
        self.secret = secrets.token_hex(32)
        self.now = 1850000000
        self.node = 'foreign-node-1234'
        with sqlite3.connect(self.db) as c:
            c.execute('CREATE TABLE nodes (id TEXT PRIMARY KEY,name TEXT,metadata TEXT)')
            c.execute('INSERT INTO nodes VALUES (?,?,?)', (self.node, 'node-kh', json.dumps({'role':'foreign','provisioning':'reserved_for_pairing'})))
        p.initialize_schema(self.db)
        g.initialize_schema(self.db)

    def issue(self, **kw):
        args = dict(master_key=self.master, admin_id='admin-1234', node_id=self.node, node_name='node-kh', domain='kh.example.com', now=self.now)
        args.update(kw)
        return g.issue(self.db, **args)

    def redeem(self, grant, **kw):
        args = dict(master_key=self.master, code=grant.code, node_id=grant.node_id, node_name=grant.node_name, control_url=grant.control_url, node_secret=self.secret, now=self.now+1)
        args.update(kw)
        return g.redeem(self.db, **args)

    def count(self, table):
        with sqlite3.connect(self.db) as c:
            return c.execute('SELECT count(*) FROM '+table).fetchone()[0]

    def test_two_hours_default_and_no_secrets_at_rest_or_repr(self):
        grant = self.issue()
        self.assertEqual(grant.expires_at, self.now+7200)
        self.assertNotIn(grant.code, repr(grant))
        self.assertTrue(self.redeem(grant))
        self.assertNotIn(grant.code.encode(), self.db.read_bytes())
        self.assertNotIn(self.secret.encode(), self.db.read_bytes())
        self.assertEqual(p.get_active_secret(self.db, master_key=self.master, node_id=self.node), self.secret.encode())

    def test_identical_retry_after_lost_reply(self):
        grant = self.issue()
        self.assertTrue(self.redeem(grant))
        self.assertTrue(self.redeem(grant, now=self.now+100))
        self.assertEqual(self.count('smite_node_identities'),1)
        self.assertEqual(self.count('smite_foreign_install_origins'),1)
        with self.assertRaises(p.PairingDenied):
            self.redeem(grant, node_secret=secrets.token_hex(32))

    def test_expiry_does_not_revoke_identity(self):
        grant = self.issue()
        self.redeem(grant)
        with self.assertRaises(p.PairingDenied):
            self.redeem(grant, now=grant.expires_at)
        self.assertEqual(p.get_active_secret(self.db, master_key=self.master, node_id=self.node), self.secret.encode())

    def test_expired_unspent_code_refused(self):
        grant = self.issue()
        with self.assertRaises(p.PairingDenied):
            self.redeem(grant, now=grant.expires_at)
        self.assertEqual(self.count('smite_node_identities'),0)

    def test_reissue_preserves_gateway_and_revokes_old_code(self):
        old = self.issue()
        new = self.issue(now=old.expires_at+1)
        self.assertEqual(old.control_url,new.control_url)
        self.assertNotEqual(old.code,new.code)
        with self.assertRaises(p.PairingDenied):
            self.redeem(old)
        self.assertTrue(self.redeem(new, now=old.expires_at+2))

    def test_changed_domain_gets_new_scope(self):
        old = self.issue()
        new = self.issue(domain='other.example.com')
        self.assertNotEqual(old.control_url,new.control_url)
        with self.assertRaises(p.PairingDenied):
            self.redeem(new,control_url=old.control_url)

    def test_pending_revocation(self):
        grant = self.issue()
        self.assertTrue(g.revoke_pending(self.db,node_id=self.node,now=self.now+1))
        with self.assertRaises(p.PairingDenied): self.redeem(grant)

    def test_cannot_reissue_paired_or_revoked_identity(self):
        grant = self.issue()
        self.redeem(grant)
        with self.assertRaises(p.PairingDenied): self.issue()
        p.revoke_node(self.db,node_id=self.node,now=self.now+2)
        with self.assertRaises(p.PairingDenied): self.issue()
        with self.assertRaises(p.PairingDenied): self.redeem(grant,now=self.now+3)

    def test_scopes_and_secrets_rejected_without_writes(self):
        grant = self.issue()
        for changes in ({'node_id':'unrelated-node'}, {'node_name':'other'}, {'control_url':'https://other.example.com:443/x'}, {'control_url':grant.control_url+'/'}, {'node_secret':'short'}, {'node_secret':True}, {'code':'smn1_wrong'}, {'code':grant.code+'x'}, {'now':self.now-1}):
            with self.subTest(changes=list(changes)), self.assertRaises(p.PairingDenied): self.redeem(grant,**changes)
        self.assertEqual(self.count('smite_node_identities'),0)
        self.assertEqual(self.count('smite_foreign_install_origins'),0)

    def test_domains_and_ttls(self):
        for domain in ('127.0.0.1','localhost','x.local','https://kh.example.com','kh.example.com:443','kh.example.com/path','a@kh.example.com','*.example.com','kh.example.com.','kh.example.com\n','a.internal','a.onion'):
            with self.subTest(domain=domain), self.assertRaises(p.PairingDenied): self.issue(domain=domain)
        for ttl in (True,59,7201,7200.0,'7200'):
            with self.subTest(ttl=ttl), self.assertRaises(p.PairingDenied): self.issue(ttl_seconds=ttl)
        self.assertEqual(self.issue(domain='KH.EXAMPLE.COM').origin,'https://kh.example.com:443')

    def test_role_name_and_reservation_binding(self):
        grant = self.issue()
        for metadata in ({'role':'iran','provisioning':'reserved_for_pairing'},{'role':'foreign'},[]):
            with sqlite3.connect(self.db) as c: c.execute('UPDATE nodes SET metadata=?',(json.dumps(metadata),))
            with self.assertRaises(p.PairingDenied): self.issue()
            with self.assertRaises(p.PairingDenied): self.redeem(grant)
        self.assertEqual(self.count('smite_node_identities'),0)

    def test_rename_after_issuance_refused(self):
        grant = self.issue()
        with sqlite3.connect(self.db) as c: c.execute("UPDATE nodes SET name='renamed'")
        with self.assertRaises(p.PairingDenied): self.redeem(grant)

    def test_legacy_outstanding_code_invalidated(self):
        legacy = p.issue_code(self.db,master_key=self.master,node_id=self.node,role='foreign',admin_id='admin',now=self.now)
        self.issue()
        with self.assertRaises(p.PairingDenied):
            p.redeem_code(self.db,master_key=self.master,code=legacy.code,node_id=self.node,role='foreign',now=self.now+1)

    def test_legacy_winner_cannot_be_rekeyed(self):
        grant=self.issue()
        legacy=p.issue_code(self.db,master_key=self.master,node_id=self.node,role='foreign',admin_id='admin',now=self.now)
        p.redeem_code(self.db,master_key=self.master,code=legacy.code,node_id=self.node,role='foreign',now=self.now+1)
        with self.assertRaises(p.PairingDenied): self.redeem(grant)
        self.assertEqual(self.count('smite_foreign_install_origins'),0)

    def test_atomic_rollback_if_origin_insert_fails(self):
        grant=self.issue()
        with sqlite3.connect(self.db) as c:
            c.execute("CREATE TRIGGER fail_origin BEFORE INSERT ON smite_foreign_install_origins BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.redeem(grant)
        self.assertEqual(self.count('smite_node_identities'),0)
        with sqlite3.connect(self.db) as c: c.execute('DROP TRIGGER fail_origin')
        self.assertTrue(self.redeem(grant))

    def test_concurrent_different_keys_only_one_wins(self):
        grant=self.issue()
        def attempt(secret):
            try: return self.redeem(grant,node_secret=secret)
            except p.PairingDenied: return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(attempt,[self.secret,secrets.token_hex(32)]))
        self.assertEqual(sum(results),1)
        self.assertEqual(self.count('smite_node_identities'),1)

    def test_same_request_concurrent_retries_one_identity(self):
        grant=self.issue()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _: self.redeem(grant),range(2)))
        self.assertEqual(results,[True,True])
        self.assertEqual(self.count('smite_node_identities'),1)

    def test_migration_idempotent_and_missing_db_not_created(self):
        g.initialize_schema(self.db)
        missing=Path(self.tmp.name)/'missing.db'
        with self.assertRaises(p.PairingDenied): g.initialize_schema(missing)
        self.assertFalse(missing.exists())


if __name__ == '__main__': unittest.main()
