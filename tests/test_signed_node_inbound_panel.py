"""Offline signed Node->Panel API integration tests (NO live VPS)."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest

from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))

from app.config import settings
from app.database import Base, get_db
from app.models import Node, Settings as DbSettings
from app import node_auth, node_pairing_store
from app.routers import signed_nodes, nodes
from app.signed_node_registration import initialize_replay_schema, _verify


class SignedInboundTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.db_path = Path(self.work.name) / "panel.db"
        self.master = Fernet.generate_key().decode("ascii")
        self.node_id = "7d2030ef-12e7-46d9-b82f-b3cfd4104000"
        self.other_id = "7d2030ef-12e7-46d9-b82f-b3cfd4104001"
        self.token = "test-frp-control-SECRET"
        self.engine = create_async_engine("sqlite+aiosqlite:///" + str(self.db_path))
        self.Session = async_sessionmaker(self.engine, expire_on_commit=False)
        async def setup():
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with self.Session() as session:
                session.add(Node(
                    id=self.node_id, name="node-kh",
                    fingerprint="fingerprint-kh-test", status="pending",
                    node_metadata={"role": "foreign", "api_address": "https://node.example.org"}
                ))
                session.add(DbSettings(key="frp", value={
                    "enabled": True, "port": 17000, "token": self.token,
                }))
                await session.commit()
        asyncio.run(setup())
        node_pairing_store.initialize_schema(self.db_path)
        approval = node_pairing_store.issue_code(
            self.db_path, master_key=self.master, node_id=self.node_id,
            role="foreign", admin_id="admin-user", now=int(time.time()),
        )
        self.secret = node_pairing_store.redeem_code(
            self.db_path, master_key=self.master, node_id=self.node_id,
            role="foreign", code=approval.code,
        ).secret.encode("ascii")

        self.old = (settings.db_path, settings.smite_node_pairing_master_key,
                    settings.smite_node_registration_mode, settings.panel_domain)
        settings.db_path = str(self.db_path)
        settings.smite_node_pairing_master_key = self.master
        settings.smite_node_registration_mode = "signed"
        settings.panel_domain = "panel.example.org"
        self.addCleanup(self.restore)

        async def database_override():
            async with self.Session() as session:
                yield session

        app = FastAPI()
        app.dependency_overrides[get_db] = database_override
        app.include_router(signed_nodes.router, prefix="/api/node-control")
        app.include_router(nodes.router, prefix="/api/nodes")
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def restore(self):
        (settings.db_path, settings.smite_node_pairing_master_key,
         settings.smite_node_registration_mode, settings.panel_domain) = self.old
        asyncio.run(self.engine.dispose())

    def request(self, *, path="/api/node-control/register", data=None, node_id=None,
                secret=None, nonce=None, timestamp=None):
        if data is None:
            data = {"node_id": self.node_id, "role": "foreign"}
        if node_id is None:
            node_id = self.node_id
        body = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        headers = node_auth.sign_request(
            secret=self.secret if secret is None else secret,
            node_id=node_id, method="POST", target=path, body=body,
            nonce=nonce, timestamp=timestamp,
        )
        return body, headers

    def test_requires_explicit_migration_and_mode(self):
        body, headers = self.request()
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=body, headers=headers
        ).status_code, 503)
        settings.smite_node_registration_mode = "legacy"
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=body, headers=headers
        ).status_code, 503)
        settings.smite_node_registration_mode = "signed"
        initialize_replay_schema(self.db_path)
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=body, headers=headers
        ).status_code, 200)

    def test_register_returns_frp_only_to_authenticated_node_and_not_legacy(self):
        initialize_replay_schema(self.db_path)
        self.assertEqual(self.client.post(
            "/api/node-control/register", json={"node_id": self.node_id, "role": "foreign"}
        ).status_code, 401)
        body, headers = self.request()
        response = self.client.post("/api/node-control/register", content=body, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.json()["id"], self.node_id)
        config = response.json()["metadata"]["frp_config"]
        self.assertEqual(config["token"], self.token)
        self.assertEqual(config["server_addr"], "panel.example.org")
        self.assertEqual(config["server_port"], 17000)
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=body, headers=headers
        ).status_code, 401)
        # The legacy registration would return a FRP secret without machine
        # auth; it is explicitly closed when strict registration is selected.
        self.assertEqual(self.client.post("/api/nodes", json={
            "name": "attacker", "ip_address": "1.2.3.4", "api_port": 8888,
            "metadata": {"role": "foreign"}
        }).status_code, 403)

    def test_authenticated_heartbeat_cannot_impersonate_node(self):
        initialize_replay_schema(self.db_path)
        path = "/api/node-control/frp-status"
        payload = {"node_id": self.node_id, "connected": True, "remote_port": 18476}
        body, headers = self.request(path=path, data=payload)
        response = self.client.post(path, content=body, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "success")
        self.assertEqual(self.client.post(path, content=body, headers=headers).status_code, 401)
        swapped = dict(payload, node_id=self.other_id)
        body, headers = self.request(path=path, data=swapped)
        self.assertEqual(self.client.post(path, content=body, headers=headers).status_code, 403)
        self.assertEqual(self.client.put(
            "/api/nodes/" + self.node_id + "/frp-status",
            json={"connected": True, "remote_port": 44444},
        ).status_code, 403)

    def test_tamper_stale_wrong_node_role_and_revocation(self):
        initialize_replay_schema(self.db_path)
        good, headers = self.request()
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=good + b" ", headers=headers
        ).status_code, 401)
        forged, headers = self.request(secret=b"a" * 64)
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=forged, headers=headers
        ).status_code, 401)
        expired, headers = self.request(timestamp=int(time.time()) - 180)
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=expired, headers=headers
        ).status_code, 401)
        wrong, headers = self.request(data={"node_id": self.node_id, "role": "iran"})
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=wrong, headers=headers
        ).status_code, 403)
        self.assertTrue(node_pairing_store.revoke_node(
            self.db_path, node_id=self.node_id
        ))
        good, headers = self.request()
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=good, headers=headers
        ).status_code, 401)

    def test_atomic_replay_across_parallel_db_users(self):
        initialize_replay_schema(self.db_path)
        body, headers = self.request(nonce="a" * 32)
        def check(_):
            try:
                return _verify(
                    method="POST", target="/api/node-control/register",
                    body=body, headers={k.lower(): v for k, v in headers.items()},
                )
            except node_auth.NodeAuthError:
                return None
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(check, range(12)))
        self.assertEqual(results.count(self.node_id), 1)


if __name__ == "__main__":
    unittest.main()
