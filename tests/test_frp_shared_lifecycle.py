"""Signed shared-FRPS child lifecycle integration tests on disposable SQLite.

No Docker, network, real signed POST, real token, or live FRPS process.
"""
from __future__ import annotations
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"panel"))
from app.database import Base
from app.models import Tunnel, Node, FrpProxyLease
from app.frp_shared_lifecycle import (
    create_shared_child, reapply_shared_child, remove_shared_child,
    verify_shared_child_listener, require_no_shared_frps_owner_dependents,
)
from app.config import settings

OWNER_ID="owner-frps-45121"
IR_ID="node-ir-test"
KH_ID="node-kh-test"
SECRET="TEST-ONLY-FRP-NOT-LIVE"

class FakeClient:
    def __init__(self, *, owner=True, apply_success=True, listener_ready=True,
                 remove_keeps_port=False):
        self.calls=[]
        self.owner=owner
        self.apply_success=apply_success
        self.listener_ready=listener_ready
        self.remove_keeps_port=remove_keeps_port
        self.applied=False
    async def get_verified_frps_owners(self, node_id):
        self.calls.append(("GET_OWNER",node_id))
        return {"status":"success","owners":[
            {"tunnel_id":OWNER_ID,"control_port":7000,"proxy_ports":[45121,49328] if (self.applied and self.listener_ready) else [45121]}
        ] if self.owner else []}
    async def send_to_node(self,node_id,endpoint,data):
        self.calls.append(("SIGNED",node_id,endpoint,data))
        if endpoint.endswith("/apply") and not self.apply_success:
            return {"status":"error","message":"UNIT_TEST_ONLY"}
        if endpoint.endswith("/apply"):
            self.applied=True
        if endpoint.endswith("/remove") and not self.remove_keeps_port:
            self.applied=False
        return {"status":"success"}

class SharedFrpsChildLifecycle(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir=tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.engine=create_async_engine("sqlite+aiosqlite:///"+str(Path(self.dir.name)/"test.db"))
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.sessions=async_sessionmaker(self.engine,expire_on_commit=False)
        self.addAsyncCleanup(self.engine.dispose)
        self.ir=Node(id=IR_ID,name="node-ir",fingerprint="ir-test-fingerprint",status="active",node_metadata={"role":"iran","ip_address":"ir.test.example"})
        self.kh=Node(id=KH_ID,name="node-kh",fingerprint="kh-test-fingerprint",status="active",node_metadata={"role":"foreign"})
        self.owner=Tunnel(id=OWNER_ID,name="trial-frp-45121",core="frp",type="tcp",node_id=IR_ID,iran_node_id=IR_ID,foreign_node_id=KH_ID,
            status="active",spec={"ports":[45121],"bind_port":7000,"token":SECRET})
        async with self.sessions() as db:
            db.add_all([self.ir,self.kh,self.owner])
            await db.commit()
        old_management=settings.smite_engine_management_mode
        old_auth=settings.smite_panel_agent_auth_mode
        settings.smite_engine_management_mode="managed"
        settings.smite_panel_agent_auth_mode="signed"
        self.addCleanup(setattr,settings,"smite_engine_management_mode",old_management)
        self.addCleanup(setattr,settings,"smite_panel_agent_auth_mode",old_auth)

    def new_request(self,port=49328):
        return type("Request",(),{
            "name":"trial-frp-"+str(port),
            "type":"tcp",
            "spec":{"shared_frps_owner":OWNER_ID,"bind_port":7000,"ports":[port],
                    "local_ip":"127.0.0.1","local_port":port,"remote_port":port}
        })()

    async def test_signed_client_only_create_retains_original_owner(self):
        client=FakeClient()
        async with self.sessions() as db:
            t=await create_shared_child(db=db,client=client,requested=self.new_request(),iran_node=self.ir,foreign_node=self.kh)
            self.assertEqual(t.status,"active")
            lease=(await db.execute(select(FrpProxyLease))).scalar_one()
            self.assertEqual((lease.remote_port,lease.owner_tunnel_id),(49328,OWNER_ID))
            owner=await db.get(Tunnel,OWNER_ID)
            self.assertEqual(owner.status,"active")
            self.assertEqual(owner.spec["token"],SECRET)
        writes=[x for x in client.calls if x[0]=="SIGNED"]
        self.assertEqual(len(writes),1)
        self.assertEqual(writes[0][1],KH_ID)
        self.assertEqual(writes[0][2],"/api/agent/tunnels/apply")
        spec=writes[0][3]["spec"]
        self.assertEqual(spec["mode"],"client")
        self.assertEqual(spec["shared_frps_owner"],OWNER_ID)
        self.assertEqual(spec["token"],SECRET)
        self.assertNotIn("token",t.spec)
        self.assertFalse(any(x[1]==IR_ID for x in writes))

    async def test_legacy_ipless_owner_uses_configured_panel_wss_domain(self):
        # Existing signed lab Node IP metadata may be absent; the trusted
        # Panel domain is enough to plan a KH WSS/443 child and must not
        # force a second IR frps. No actual socket or network is used.
        client=FakeClient()
        old_domain=settings.panel_domain
        settings.panel_domain="ir.test.example"
        try:
            self.ir.node_metadata={"role":"iran"}
            async with self.sessions() as db:
                t=await create_shared_child(
                    db=db,client=client,requested=self.new_request(),
                    iran_node=self.ir,foreign_node=self.kh)
                self.assertEqual(t.status,"active")
                sends=[x for x in client.calls if x[0]=="SIGNED"]
                self.assertEqual(len(sends),1)
                self.assertEqual(sends[0][1],KH_ID)
                self.assertEqual(sends[0][3]["spec"]["server_addr"],"ir.test.example")
                self.assertIsNotNone((await db.execute(select(FrpProxyLease))).scalar_one_or_none())
        finally:
            settings.panel_domain=old_domain

    async def test_ipless_owner_without_panel_domain_fails_closed(self):
        client=FakeClient()
        old_domain=settings.panel_domain
        settings.panel_domain=""
        try:
            self.ir.node_metadata={"role":"iran"}
            async with self.sessions() as db:
                with self.assertRaises(Exception) as cm:
                    await create_shared_child(
                        db=db,client=client,requested=self.new_request(),
                        iran_node=self.ir,foreign_node=self.kh)
                self.assertEqual(getattr(cm.exception,"status_code",None),409)
                self.assertFalse(any(x[0]=="SIGNED" for x in client.calls))
        finally:
            settings.panel_domain=old_domain

    async def test_unconfirmed_apply_keeps_row_and_lease_for_reconcile(self):
        client=FakeClient(apply_success=False)
        async with self.sessions() as db:
            t=await create_shared_child(db=db,client=client,requested=self.new_request(),iran_node=self.ir,foreign_node=self.kh)
            self.assertEqual(t.status,"error")
            self.assertIsNotNone((await db.execute(select(FrpProxyLease))).scalar_one_or_none())
            with self.assertRaises(Exception) as cm:
                await create_shared_child(db=db,client=FakeClient(),requested=self.new_request(),iran_node=self.ir,foreign_node=self.kh)
            self.assertEqual(getattr(cm.exception,"status_code",None),409)

    async def test_read_only_owner_proof_denial_emits_no_apply(self):
        client=FakeClient(owner=False)
        async with self.sessions() as db:
            with self.assertRaises(Exception) as cm:
                await create_shared_child(db=db,client=client,requested=self.new_request(),iran_node=self.ir,foreign_node=self.kh)
            self.assertEqual(getattr(cm.exception,"status_code",None),409)
            self.assertFalse(any(x[0]=="SIGNED" for x in client.calls))
            self.assertIsNone((await db.execute(select(FrpProxyLease))).scalar_one_or_none())

    async def test_signed_reapply_only_targets_foreign_client(self):
        client=FakeClient()
        async with self.sessions() as db:
            t=await create_shared_child(db=db,client=client,requested=self.new_request(),iran_node=self.ir,foreign_node=self.kh)
            client.calls.clear()
            result=await reapply_shared_child(db=db,client=client,tunnel=t)
            self.assertEqual(result["status"],"applied")
        writes=[c for c in client.calls if c[0]=="SIGNED"]
        self.assertEqual(len(writes),1)
        self.assertEqual(writes[0][1],KH_ID)

    async def test_remove_never_sends_command_to_ir_owner(self):
        client=FakeClient()
        async with self.sessions() as db:
            t=await create_shared_child(db=db,client=client,requested=self.new_request(),iran_node=self.ir,foreign_node=self.kh)
            client.calls.clear()
            result=await remove_shared_child(db=db,client=client,tunnel=t)
            self.assertEqual(result["status"],"deleted")
            self.assertIsNone((await db.execute(select(FrpProxyLease))).scalar_one_or_none())
            self.assertIsNotNone(await db.get(Tunnel,OWNER_ID))
        self.assertEqual([x[1:3] for x in client.calls if x[0]=="SIGNED"],[(KH_ID,"/api/agent/tunnels/remove")])

    async def test_pending_until_signed_ir_listener_then_verify_without_post(self):
        client=FakeClient(listener_ready=False)
        async with self.sessions() as db:
            t=await create_shared_child(db=db,client=client,requested=self.new_request(),iran_node=self.ir,foreign_node=self.kh)
            self.assertEqual(t.status,"pending")
            client.calls.clear()
            report=await verify_shared_child_listener(db=db,client=client,tunnel=t)
            self.assertEqual(report["status"],"pending")
            self.assertFalse(any(x[0]=="SIGNED" for x in client.calls))
            client.listener_ready=True
            report=await verify_shared_child_listener(db=db,client=client,tunnel=t)
            self.assertEqual(report["status"],"active")
            self.assertEqual(t.status,"active")
            self.assertFalse(any(x[0]=="SIGNED" for x in client.calls))

    async def test_successful_kh_remove_but_ir_listener_still_present_holds_lease(self):
        client=FakeClient(remove_keeps_port=True)
        async with self.sessions() as db:
            child=await create_shared_child(
                db=db,client=client,requested=self.new_request(),
                iran_node=self.ir,foreign_node=self.kh)
            self.assertEqual(child.status,"active")
            client.calls.clear()
            with self.assertRaises(Exception) as cm:
                await remove_shared_child(db=db,client=client,tunnel=child)
            self.assertEqual(getattr(cm.exception,"status_code",None),409)
            self.assertIsNotNone(await db.get(Tunnel,child.id))
            lease=(await db.execute(select(FrpProxyLease))).scalar_one()
            self.assertEqual(lease.remote_port,49328)
            self.assertIsNotNone(await db.get(Tunnel,OWNER_ID))
        self.assertEqual(
            [x[1:3] for x in client.calls if x[0]=="SIGNED"],
            [(KH_ID,"/api/agent/tunnels/remove")])
        self.assertFalse(any(x[0]=="SIGNED" and x[1]==IR_ID for x in client.calls))

    async def test_missing_signed_ir_release_proof_holds_lease(self):
        client=FakeClient()
        async with self.sessions() as db:
            child=await create_shared_child(
                db=db,client=client,requested=self.new_request(),
                iran_node=self.ir,foreign_node=self.kh)
            async def unavailable(_node_id):
                return {"status":"error","message":"TEST_ONLY_NO_SIGNED_PROOF"}
            client.get_verified_frps_owners=unavailable
            with self.assertRaises(Exception) as cm:
                await remove_shared_child(db=db,client=client,tunnel=child)
            self.assertEqual(getattr(cm.exception,"status_code",None),409)
            self.assertIsNotNone(await db.get(Tunnel,child.id))
            self.assertIsNotNone((await db.execute(select(FrpProxyLease))).scalar_one_or_none())
            self.assertIsNotNone(await db.get(Tunnel,OWNER_ID))

    async def test_failed_remove_keeps_child_lease_and_owner(self):
        client=FakeClient()
        async with self.sessions() as db:
            t=await create_shared_child(db=db,client=client,requested=self.new_request(),iran_node=self.ir,foreign_node=self.kh)
            async def failed(*args,**kwargs):
                return {"status":"error"}
            client.send_to_node=failed
            with self.assertRaises(Exception) as cm:
                await remove_shared_child(db=db,client=client,tunnel=t)
            self.assertEqual(getattr(cm.exception,"status_code",None),409)
            self.assertIsNotNone((await db.execute(select(FrpProxyLease))).scalar_one_or_none())
            self.assertIsNotNone(await db.get(Tunnel,t.id))

    async def test_orphan_lease_prevents_owner_removal_after_child_row_loss(self):
        # Simulates inconsistent recovery state: child JSON row missing, but
        # durable lease still reserves 49328. Owner must not be removed.
        async with self.sessions() as db:
            db.add(FrpProxyLease(
                tunnel_id="orphan-shared-child", iran_node_id=IR_ID,
                foreign_node_id=KH_ID, owner_tunnel_id=OWNER_ID,
                remote_port=49328))
            await db.commit()
            with self.assertRaises(Exception) as cm:
                await require_no_shared_frps_owner_dependents(
                    db=db, owner_tunnel_id=OWNER_ID)
            self.assertEqual(getattr(cm.exception,"status_code",None),409)
            self.assertIsNotNone(await db.get(Tunnel,OWNER_ID))

    async def test_child_marker_prevents_owner_removal_without_lease(self):
        # Historical migrated child may be present even if the lease table
        # has not been populated. Do not permit owner deletion then.
        async with self.sessions() as db:
            child=Tunnel(
                id="legacy-shared-child", name="legacy-shared-child",
                core="frp", type="tcp", node_id=IR_ID,
                iran_node_id=IR_ID, foreign_node_id=KH_ID,
                spec={"shared_frps_owner":OWNER_ID,"ports":[49328]},
                status="error")
            db.add(child)
            await db.commit()
            with self.assertRaises(Exception) as cm:
                await require_no_shared_frps_owner_dependents(
                    db=db, owner_tunnel_id=OWNER_ID)
            self.assertEqual(getattr(cm.exception,"status_code",None),409)
            self.assertIsNotNone(await db.get(Tunnel,OWNER_ID))

    async def test_lease_free_owner_is_not_falsely_blocked(self):
        async with self.sessions() as db:
            await require_no_shared_frps_owner_dependents(
                db=db, owner_tunnel_id=OWNER_ID)

    def test_router_owner_and_global_reapply_gates_use_durable_leases(self):
        source=(ROOT/"panel/app/routers/tunnels.py").read_text()
        self.assertGreaterEqual(
            source.count("require_no_shared_frps_owner_dependents("),2)
        self.assertIn("select(FrpProxyLease.tunnel_id)",source)

    async def test_legacy_auth_cannot_authorize_shared_child(self):
        client=FakeClient()
        settings.smite_panel_agent_auth_mode="legacy"
        async with self.sessions() as db:
            with self.assertRaises(Exception) as cm:
                await create_shared_child(db=db,client=client,requested=self.new_request(),iran_node=self.ir,foreign_node=self.kh)
            self.assertEqual(getattr(cm.exception,"status_code",None),409)
            self.assertEqual(client.calls,[])

if __name__=="__main__":
    unittest.main()
