"""Offline approval snapshot and actual HTTPX/HTTPCore connection-boundary tests."""
import asyncio
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import sys
import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'panel'))
import test_foreign_install_grants as grant_tests
from app.config import settings
from app import signed_node_origins as origins
from app import signed_agent_transport as transport
import httpx
import httpcore
from httpcore._backends.mock import AsyncMockStream, AsyncMockBackend


class OriginTests(unittest.TestCase):
    setUpFixture = grant_tests.Grants.setUp
    issue = grant_tests.Grants.issue
    redeem = grant_tests.Grants.redeem

    def setUp(self):
        self.setUpFixture()
        self.file = Path(self.tmp.name) / 'trusted' / 'origins.json'
        self.file.parent.mkdir(mode=0o700)
        for key, value in dict(db_path=str(self.db), db_type='sqlite',
                smite_signed_node_origins_path=str(self.file),
                smite_foreign_install_enabled=False,
                smite_foreign_install_origin_trust_enabled=True).items():
            old = getattr(settings, key)
            setattr(settings, key, value)
            self.addCleanup(setattr, settings, key, old)
        self.grant = self.issue()
        self.redeem(self.grant)

    def write_file(self, **changes):
        record = dict(role='foreign', node_name='node-kh', origin=self.grant.origin,
                      control_url=self.grant.control_url)
        record.update(changes)
        self.file.write_text(json.dumps({'version':1,'nodes':{self.node:record}}))
        self.file.chmod(0o600)

    def sql(self, query):
        with sqlite3.connect(self.db) as db:
            db.execute(query)

    def test_valid_consumed_origin_and_expiry_independent_of_issuance(self):
        # Fixture timestamps deliberately independent of wall clock; expiry is
        # checked at consumption, not at each later authenticated command.
        result = origins.approved_node(self.node)
        self.assertEqual(result['origin_source'], 'installation_grant')
        self.assertEqual(result['control_url'], self.grant.control_url)
        self.assertFalse(settings.smite_foreign_install_enabled)

    def test_trust_default_off(self):
        self.assertFalse(type(settings).model_fields['smite_foreign_install_origin_trust_enabled'].default)
        settings.smite_foreign_install_origin_trust_enabled=False
        with self.assertRaises(origins.ApprovedOriginUnavailable): origins.approved_node(self.node)

    def test_identical_file_still_requires_pinned_transport(self):
        self.write_file()
        self.assertEqual(origins.approved_node(self.node)['origin_source'], 'installation_grant')

    def test_conflicting_file_denied(self):
        self.write_file(control_url=self.grant.origin+'/smite-node/'+'a'*32)
        with self.assertRaises(origins.ApprovedOriginUnavailable): origins.approved_node(self.node)

    def test_unsafe_or_invalid_file_never_falls_back(self):
        for data, mode in [('broken',0o600), ('{}',0o600), ('{}',0o644)]:
            self.file.write_text(data); self.file.chmod(mode)
            with self.assertRaises(origins.ApprovedOriginUnavailable): origins.approved_node(self.node)

    def test_revoked_identity_denied_even_with_matching_file(self):
        self.write_file()
        self.sql('UPDATE smite_node_identities SET revoked_at=1')
        with self.assertRaises(origins.ApprovedOriginUnavailable): origins.approved_node(self.node)

    def test_all_binding_evidence_required(self):
        for mutation in [
            "UPDATE smite_foreign_install_grants SET consumed_at=NULL",
            "UPDATE smite_foreign_install_grants SET revoked_at=1",
            "UPDATE smite_foreign_install_grants SET node_name='other'",
            "UPDATE smite_foreign_install_grants SET expires_at=issued_at",
            "UPDATE smite_foreign_install_origins SET approved_at=0",
            "UPDATE smite_node_identities SET node_role='iran'",
            "UPDATE nodes SET name='other'",
            "UPDATE nodes SET metadata='{}'",
            "DELETE FROM smite_node_identities",
            "DELETE FROM smite_foreign_install_grants",
        ]:
            with self.subTest(mutation=mutation):
                backup=self.db.read_bytes()
                self.sql(mutation)
                with self.assertRaises(origins.ApprovedOriginUnavailable): origins.approved_node(self.node)
                self.db.write_bytes(backup)

    def test_missing_schema_does_not_create_or_fallback(self):
        self.write_file()
        self.sql('DROP TABLE smite_foreign_install_origins')
        before=self.db.read_bytes()
        with self.assertRaises(origins.ApprovedOriginUnavailable): origins.approved_node(self.node)
        self.assertEqual(self.db.read_bytes(),before)

    def test_file_only_node_preserved(self):
        self.write_file()
        self.sql('DELETE FROM smite_foreign_install_origins')
        self.sql('DELETE FROM smite_foreign_install_grants')
        self.assertNotIn('origin_source',origins.approved_node(self.node))

    def test_missing_committed_origin_never_downgrades_to_file(self):
        self.write_file()
        self.sql('DELETE FROM smite_foreign_install_origins')
        with self.assertRaises(origins.ApprovedOriginUnavailable): origins.approved_node(self.node)

    def test_signed_checkin_name_remains_bound(self):
        self.sql('UPDATE nodes SET metadata=\'{"role":"foreign","provisioning":"signed_checkin"}\'')
        self.assertEqual(origins.approved_node(self.node)['node_name'],'node-kh')


class DNSAndWireTests(unittest.IsolatedAsyncioTestCase):
    def records(self, addresses):
        return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM,
                 socket.IPPROTO_TCP, '', (ip,443)) for ip in addresses]

    async def test_dns_public_and_mixed_private_denials(self):
        for blocked in ['127.0.0.1','10.0.0.1','169.254.169.254','100.64.0.1',
                        '192.0.2.1','192.0.0.8','192.88.99.1','3fff::1','224.0.0.1','0.0.0.0','::1','fc00::1',
                        'fe80::1','::ffff:8.8.8.8','64:ff9b::808:808','2002:0808:0808::1']:
            with self.subTest(ip=blocked), patch.object(asyncio.get_running_loop(), 'getaddrinfo',
                    AsyncMock(return_value=self.records(['8.8.8.8',blocked]))):
                with self.assertRaises(transport.SignedAgentUnavailable):
                    await transport.resolve_public_address('kh.example.com',1)
        with patch.object(asyncio.get_running_loop(),'getaddrinfo',
                          AsyncMock(return_value=self.records(['2606:4700:4700::1111']))):
            self.assertEqual(await transport.resolve_public_address('kh.example.com',1),'2606:4700:4700::1111')

    async def test_dns_empty_failure_timeout(self):
        for result in [[],socket.gaierror('fixture'),asyncio.TimeoutError()]:
            resolver=AsyncMock(side_effect=result) if isinstance(result,Exception) else AsyncMock(return_value=result)
            with patch.object(asyncio.get_running_loop(),'getaddrinfo',resolver):
                with self.assertRaises(transport.SignedAgentUnavailable):
                    await transport.resolve_public_address('kh.example.com',0.1)

    async def wire(self, ip, fail_tls=False):
        seen={}
        class Stream(AsyncMockStream):
            async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
                seen.update(hostname=server_hostname, cert=ssl_context.verify_mode,
                            check_hostname=ssl_context.check_hostname)
                if fail_tls: raise httpcore.ConnectError('certificate verify failed')
                return self
            async def write(self, buffer, timeout=None):
                seen['wire']=seen.get('wire',b'')+buffer
        class Backend(AsyncMockBackend):
            async def connect_tcp(self, host, port, **kw):
                seen['dial']=(host,port)
                return Stream([b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'])
        pinned=transport.PublicPinnedTransport('kh.example.com',ip)
        pinned._pool._network_backend=Backend([])
        async with httpx.AsyncClient(transport=pinned,trust_env=False,follow_redirects=False) as client:
            try:
                result=await client.post('https://kh.example.com/smite-node/'+'a'*32+'/api/agent/status',content=b'{}')
                self.assertEqual(result.status_code,200)
            except httpx.ConnectError:
                if not fail_tls: raise
        self.assertEqual(seen['dial'],(ip,443))
        self.assertEqual(seen['hostname'],'kh.example.com')
        self.assertEqual(seen['cert'],ssl.CERT_REQUIRED)
        self.assertTrue(seen['check_hostname'])
        if fail_tls: self.assertNotIn('wire',seen)
        else:
            self.assertIn(b'Host: kh.example.com\r\n',seen['wire'])
            self.assertIn(b'/api/agent/status HTTP/1.1',seen['wire'])

    async def test_actual_httpcore_dials_pinned_ipv4_with_original_host_and_sni(self):
        await self.wire('8.8.8.8')

    async def test_actual_httpcore_dials_pinned_ipv6_with_original_host_and_sni(self):
        await self.wire('2606:4700:4700::1111')

    async def test_certificate_failure_sends_no_credentials(self):
        await self.wire('8.8.8.8',fail_tls=True)

    async def test_private_dns_rejected_before_key_read_or_transport(self):
        with patch.object(transport,'resolve_public_address',AsyncMock(side_effect=transport.SignedAgentUnavailable('blocked'))), \
             patch.object(transport,'get_paired_key') as key, patch.object(transport,'PublicPinnedTransport') as client:
            with self.assertRaises(transport.SignedAgentUnavailable):
                await transport.signed_agent_call(node_id='foreign-node-1234',address='https://kh.example.com',using_frp=False,
                    method='GET',target='/api/agent/status',gateway_control_url='https://kh.example.com/smite-node/'+'a'*32,
                    pin_public_dns=True)
            key.assert_not_called(); client.assert_not_called()

    async def test_signed_call_pins_once_preserves_hmac_and_refuses_redirect(self):
        from app import node_auth
        for status in (200, 302):
            seen=[]
            secret=b'a'*64
            async def handle(request):
                seen.append(request)
                self.assertTrue(node_auth.verify_request(secret=secret,node_id='foreign-node-1234',
                    method='POST',target='/api/agent/tunnels/apply',body=await request.aread(),
                    headers=request.headers,replay=node_auth.NonceWindow()))
                return httpx.Response(status,json={'status':'ok'},headers={'Location':'http://127.0.0.1/'})
            with patch.object(transport,'resolve_public_address',AsyncMock(return_value='8.8.8.8')) as dns, \
                 patch.object(transport,'PublicPinnedTransport',return_value=httpx.MockTransport(handle)) as pin, \
                 patch.object(transport,'get_paired_key',return_value=secret):
                args=dict(node_id='foreign-node-1234',address='https://kh.example.com',using_frp=False,
                          method='POST',target='/api/agent/tunnels/apply',payload={'test':True},
                          gateway_control_url='https://kh.example.com/smite-node/'+'a'*32,pin_public_dns=True)
                if status==200: self.assertEqual((await transport.signed_agent_call(**args))['status'],'ok')
                else:
                    with self.assertRaises(transport.SignedAgentUnavailable): await transport.signed_agent_call(**args)
                dns.assert_awaited_once()
                pin.assert_called_once_with('kh.example.com','8.8.8.8')
                self.assertEqual(len(seen),1)

    async def test_nodeclient_routes_database_approval_through_pinning(self):
        from app.node_client import NodeClient
        node=SimpleNamespace(id='foreign-node-1234',name='node-kh',status='active',
            node_metadata={'role':'foreign','node_name':'node-kh','provisioning':'signed_checkin'})
        session=AsyncMock()
        session.execute.return_value=MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value=node
        factory=MagicMock()
        factory.return_value.__aenter__=AsyncMock(return_value=session)
        factory.return_value.__aexit__=AsyncMock(return_value=None)
        pin=dict(node_id=node.id,node_name=node.name,role='foreign',origin='https://kh.example.com:443',
                 control_url='https://kh.example.com:443/smite-node/'+'a'*32,origin_source='installation_grant')
        with patch('app.node_client.AsyncSessionLocal',factory), \
             patch('app.node_client.approved_node',return_value=pin), \
             patch('app.node_client.signed_agent_call',AsyncMock(return_value={'status':'ok'})) as call:
            result=await NodeClient()._signed_agent_request(node.id,method='GET',target='/api/agent/status')
            self.assertEqual(result,{'status':'ok'})
            self.assertTrue(call.call_args.kwargs['pin_public_dns'])
            self.assertEqual(call.call_args.kwargs['gateway_control_url'],pin['control_url'])

    async def test_no_cross_origin_requests(self):
        async with transport.PublicPinnedTransport('kh.example.com','8.8.8.8') as pinned:
            with self.assertRaises(transport.SignedAgentUnavailable):
                await pinned.handle_async_request(httpx.Request('GET','https://other.example.com/api/agent/status'))

if __name__ == '__main__': unittest.main()
