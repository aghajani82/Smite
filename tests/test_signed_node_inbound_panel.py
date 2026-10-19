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
from unittest.mock import AsyncMock, patch

from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))

from app.config import settings
from app.database import Base, get_db
from app.models import Node, Admin, Settings as DbSettings
from app.routers import auth
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
                    node_metadata={"role": "foreign", "node_name": "node-kh", "provisioning": "reserved_for_pairing", "control_address": "https://node.example.org/control/secure/", "api_address": "https://node.example.org"}
                ))
                session.add(DbSettings(key="frp", value={
                    "enabled": True, "port": 17000, "token": self.token,
                }))
                session.add(Admin(id="admin0000-1111-2222-3333-444444444444", username="test-admin", password_hash="not-used"))
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

        # Administrator-approved origin is deliberately independent of
        # legacy self-reported Node metadata.
        private = Path(self.work.name) / "trusted-nodes"
        private.mkdir(mode=0o700)
        pins = private / "approved-origins.json"
        pins.write_text(json.dumps({"version": 1, "nodes": {
            self.node_id: {"role": "foreign", "node_name": "node-kh",
                           "origin": "https://node.example.org:443",
                           "control_url": "https://node.example.org/control/secure/"}
        }}))
        pins.chmod(0o600)
        self.old = (settings.db_path, settings.smite_node_pairing_master_key,
                    settings.smite_node_registration_mode, settings.panel_domain,
                    settings.smite_panel_agent_auth_mode,
                    settings.smite_signed_node_origins_path)
        settings.smite_signed_node_origins_path = str(pins)
        settings.db_path = str(self.db_path)
        settings.smite_node_pairing_master_key = self.master
        settings.smite_node_registration_mode = "signed"
        settings.panel_domain = "panel.example.org"
        settings.smite_panel_agent_auth_mode = "signed"
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
         settings.smite_node_registration_mode, settings.panel_domain,
         settings.smite_panel_agent_auth_mode,
         settings.smite_signed_node_origins_path) = self.old
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

    def test_reserved_foreign_node_only_becomes_paired_after_signed_checkin(self):
        # Fresh clean-RC KH is offline: admin creates pending slot first.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE nodes SET status='pending', metadata=? WHERE id=?",
                (json.dumps({"role": "foreign", "node_name": "node-kh",
                             "provisioning": "reserved_for_pairing"}), self.node_id),
            )
        initialize_replay_schema(self.db_path)
        # No HMAC credentials: cannot make pending state appear paired.
        rejected = self.client.post("/api/node-control/register", json={
            "node_id": self.node_id, "role": "foreign"
        })
        self.assertEqual(rejected.status_code, 401)
        with sqlite3.connect(self.db_path) as conn:
            status, meta = conn.execute(
                "SELECT status, metadata FROM nodes WHERE id=?", (self.node_id,)
            ).fetchone()
            self.assertEqual(status, "pending")
            self.assertEqual(json.loads(meta)["provisioning"], "reserved_for_pairing")
        body, headers = self.request()
        accepted = self.client.post("/api/node-control/register", content=body, headers=headers)
        self.assertEqual(accepted.status_code, 200, accepted.text)
        with sqlite3.connect(self.db_path) as conn:
            status, meta = conn.execute(
                "SELECT status, metadata FROM nodes WHERE id=?", (self.node_id,)
            ).fetchone()
            self.assertEqual(status, "active")
            self.assertEqual(json.loads(meta)["provisioning"], "signed_checkin")
        self.assertEqual(
            self.client.post("/api/node-control/register", content=body, headers=headers).status_code,
            401,
        )

    def test_frp_admission_failure_does_not_mark_pending_node_active(self):
        """A signed but unsuccessful check-in must not fake Connected."""
        initialize_replay_schema(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE nodes SET status='pending', metadata=? WHERE id=?",
                (json.dumps({
                    "role": "foreign", "node_name": "node-kh",
                    "provisioning": "reserved_for_pairing",
                }), self.node_id),
            )
        original_domain = settings.panel_domain
        try:
            for failing in ("host", "token", "port"):
                with self.subTest(failing=failing):
                    if failing == "host":
                        settings.panel_domain = "broken host"
                        config = {"enabled": True, "port": 17000, "token": self.token}
                    elif failing == "token":
                        settings.panel_domain = "panel.example.org"
                        config = {"enabled": True, "port": 17000, "token": ""}
                    else:
                        settings.panel_domain = "panel.example.org"
                        config = {"enabled": True, "port": 0, "token": self.token}
                    with sqlite3.connect(self.db_path) as conn:
                        conn.execute(
                            "UPDATE settings SET value=? WHERE key='frp'",
                            (json.dumps(config),),
                        )
                    body, headers = self.request()
                    rejected = self.client.post(
                        "/api/node-control/register", content=body, headers=headers,
                    )
                    self.assertEqual(rejected.status_code, 503, rejected.text)
                    with sqlite3.connect(self.db_path) as conn:
                        row = conn.execute(
                            "SELECT status, metadata FROM nodes WHERE id=?",
                            (self.node_id,),
                        ).fetchone()
                    self.assertEqual(row[0], "pending")
                    self.assertEqual(
                        json.loads(row[1])["provisioning"], "reserved_for_pairing"
                    )

            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE settings SET value=? WHERE key='frp'",
                    (json.dumps({"enabled": True, "port": 17000,
                                 "token": self.token}),),
                )
            body, headers = self.request()
            ok = self.client.post(
                "/api/node-control/register", content=body, headers=headers
            )
            self.assertEqual(ok.status_code, 200, ok.text)
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT status, metadata FROM nodes WHERE id=?",
                    (self.node_id,),
                ).fetchone()
            self.assertEqual(row[0], "active")
            self.assertEqual(json.loads(row[1])["provisioning"], "signed_checkin")
        finally:
            settings.panel_domain = original_domain

    def test_signed_panel_commands_require_checkin_and_admin_name_pin(self):
        """A redeemed key, legacy active row, or changed name is never readiness."""
        from app.node_client import NodeClient

        def update(status, mark, name="node-kh", meta_name="node-kh"):
            with sqlite3.connect(self.db_path) as connection:
                connection.execute(
                    "UPDATE nodes SET status=?,name=?,metadata=? WHERE id=?",
                    (status, name, json.dumps({
                        "role": "foreign", "node_name": meta_name,
                        "provisioning": mark, "api_address": "http://unsafe.test:8888",
                    }), self.node_id),
                )

        client = NodeClient()
        with (
            patch("app.node_client.AsyncSessionLocal", self.Session),
            patch("app.node_client.signed_agent_call", new_callable=AsyncMock) as call,
        ):
            call.return_value = {"status": "ok", "active_tunnels": 0}

            def status():
                return asyncio.run(client.get_tunnel_status(self.node_id))

            for state, marker in (
                ("pending", "reserved_for_pairing"),
                ("active", "reserved_for_pairing"),
                ("active", None),
                ("pending", "signed_checkin"),
            ):
                with self.subTest(state=state, marker=marker):
                    update(state, marker)
                    self.assertEqual(status()["status"], "error")
            call.assert_not_awaited()

            update("pending", "reserved_for_pairing")
            initialize_replay_schema(self.db_path)
            body, headers = self.request()
            response = self.client.post(
                "/api/node-control/register", content=body, headers=headers
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(status()["status"], "ok")
            call.assert_awaited_once()
            call.reset_mock()

            update("active", "signed_checkin", name="wrong-name")
            self.assertEqual(status()["status"], "error")
            update("active", "signed_checkin", meta_name="wrong-name")
            self.assertEqual(status()["status"], "error")
            update("pending", "signed_checkin")
            self.assertEqual(status()["status"], "error")
            call.assert_not_awaited()

    def test_authenticated_heartbeat_cannot_impersonate_node(self):
        initialize_replay_schema(self.db_path)
        path = "/api/node-control/frp-status"
        payload = {"node_id": self.node_id, "connected": True, "remote_port": 18476}
        body, headers = self.request(path=path, data=payload)
        pending = self.client.post(path, content=body, headers=headers)
        self.assertEqual(pending.status_code, 403, pending.text)
        with sqlite3.connect(self.db_path) as conn:
            status, raw_meta = conn.execute(
                "SELECT status,metadata FROM nodes WHERE id=?", (self.node_id,)
            ).fetchone()
        self.assertEqual(status, "pending")
        self.assertNotIn("frp_connected", json.loads(raw_meta))
        # Only an authenticated signed registration may enable telemetry.
        register_body, register_headers = self.request()
        registered = self.client.post(
            "/api/node-control/register",
            content=register_body, headers=register_headers,
        )
        self.assertEqual(registered.status_code, 200, registered.text)
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

    def test_list_get_restricted_in_signed_mode_and_delete_always_admin(self):
        token = auth.create_access_token({"sub": "test-admin"})
        headers = {"Authorization": "Bearer " + token}
        for url in ("/api/nodes", "/api/nodes/" + self.node_id):
            self.assertIn(self.client.get(url).status_code, (401, 403))
            self.assertIn(self.client.get(
                url, headers={"Authorization": "Bearer bad"}
            ).status_code, (401, 403))
        with patch("app.routers.nodes.NodeClient.get_tunnel_status",
                   new_callable=AsyncMock, return_value={"status": "ok"}) as probe:
            result = self.client.get("/api/nodes", headers=headers)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(len(result.json()), 1)
        self.assertEqual(
            result.json()[0]["metadata"]["connection_status"],
            "waiting-for-pairing",
        )
        probe.assert_not_awaited()
        # Even an FRP hint inserted in the DB cannot bypass pending status.
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE nodes SET metadata=? WHERE id=?",
                (json.dumps({"role": "foreign", "node_name": "node-kh",
                             "frp_connected": True}), self.node_id),
            )
        with patch("app.routers.nodes.NodeClient.get_tunnel_status",
                   new_callable=AsyncMock, return_value={"status": "ok"}) as probe:
            pending = self.client.get("/api/nodes", headers=headers)
        self.assertEqual(
            pending.json()[0]["metadata"]["connection_status"],
            "waiting-for-pairing",
        )
        probe.assert_not_awaited()
        self.assertEqual(
            self.client.get("/api/nodes/" + self.node_id, headers=headers).status_code, 200
        )
        self.assertIn(self.client.delete("/api/nodes/" + self.node_id).status_code, (401, 403))
        settings.smite_node_registration_mode = "legacy"
        self.assertIn(self.client.delete("/api/nodes/" + self.node_id).status_code, (401, 403))
        settings.smite_node_registration_mode = "signed"

    def test_gateway_check_bound_to_signed_identity_and_own_endpoint(self):
        initialize_replay_schema(self.db_path)
        path = "/api/node-control/gateway-check"
        params = {"node_id": self.node_id, "node_name": "node-kh",
                  "control_url": "https://node.example.org/control/secure/"}
        self.assertEqual(self.client.post(path, json=params).status_code, 401)
        body, headers = self.request(path=path, data=params)
        with patch("app.routers.signed_nodes.NodeClient.get_tunnel_status",
                   new_callable=AsyncMock, return_value={"status": "ok"}) as check:
            pending = self.client.post(path, content=body, headers=headers)
        self.assertEqual(pending.json(), {"status": "ok", "gateway_ready": False})
        check.assert_not_awaited()
        register_body, register_headers = self.request()
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=register_body,
            headers=register_headers,
        ).status_code, 200)
        body, headers = self.request(path=path, data=params)
        with patch("app.routers.signed_nodes.NodeClient.get_tunnel_status",
                   new_callable=AsyncMock, return_value={"status": "ok"}) as check:
            res = self.client.post(path, content=body, headers=headers)
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json(), {"status": "ok", "gateway_ready": True})
        self.assertEqual(res.headers["cache-control"], "no-store")
        check.assert_awaited_once_with(self.node_id)
        self.assertEqual(self.client.post(path, content=body, headers=headers).status_code, 401)
        params["control_url"] = "https://node.example.org/wrong/path"
        body, headers = self.request(path=path, data=params)
        with patch("app.routers.signed_nodes.NodeClient.get_tunnel_status",
                   new_callable=AsyncMock) as check:
            wrong = self.client.post(path, content=body, headers=headers)
        self.assertEqual(wrong.json(), {"status": "ok", "gateway_ready": False})
        check.assert_not_awaited()
        settings.smite_panel_agent_auth_mode = "legacy"
        body, headers = self.request(path=path, data=params)
        self.assertEqual(self.client.post(path, content=body, headers=headers).status_code, 503)

    def test_stale_signed_frp_hint_cannot_fake_connected_status(self):
        """An authenticated failure beats last known FRP telemetry."""
        initialize_replay_schema(self.db_path)
        body, headers = self.request()
        self.assertEqual(
            self.client.post("/api/node-control/register",
                             content=body, headers=headers).status_code, 200
        )
        with sqlite3.connect(self.db_path) as database:
            database.execute(
                "UPDATE nodes SET metadata=? WHERE id=?",
                (json.dumps({"role": "foreign", "node_name": "node-kh",
                             "provisioning": "signed_checkin",
                             "frp_connected": True, "frp_remote_port": 18476}),
                 self.node_id),
            )
        token = auth.create_access_token({"sub": "test-admin"})
        headers = {"Authorization": "Bearer " + token}
        with patch("app.routers.nodes.NodeClient.get_tunnel_status",
                   new_callable=AsyncMock, return_value={
                       "status": "error", "message": "connection timeout"
                   }) as probe:
            response = self.client.get("/api/nodes", headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()[0]
        self.assertEqual(data["metadata"]["connection_status"], "reconnecting")
        self.assertNotEqual(data["metadata"]["connection_status"], "connected")
        probe.assert_awaited_once()

    def test_gateway_check_rejects_each_name_mismatch_and_no_probe(self):
        """Both DB Node.name and approved metadata name must match exactly."""
        initialize_replay_schema(self.db_path)
        reg_body, reg_headers = self.request()
        self.assertEqual(self.client.post(
            "/api/node-control/register", content=reg_body,
            headers=reg_headers,
        ).status_code, 200)
        path = "/api/node-control/gateway-check"
        data = {"node_id": self.node_id, "node_name": "node-kh",
                "control_url": "https://node.example.org/control/secure/"}
        for column in ("name", "metadata"):
            with sqlite3.connect(self.db_path) as conn:
                if column == "name":
                    conn.execute(
                        "UPDATE nodes SET name=? WHERE id=?",
                        ("unexpected-node", self.node_id),
                    )
                else:
                    conn.execute(
                        "UPDATE nodes SET metadata=? WHERE id=?",
                        (json.dumps({"role": "foreign", "node_name": "unexpected-node",
                                     "provisioning": "signed_checkin"}), self.node_id),
                    )
            body, headers = self.request(path=path, data=data)
            with patch("app.routers.signed_nodes.NodeClient.get_tunnel_status",
                       new_callable=AsyncMock, return_value={"status": "ok"}) as checker:
                denied = self.client.post(path, content=body, headers=headers)
            self.assertEqual(
                denied.json(), {"status": "ok", "gateway_ready": False},
                (column, denied.text),
            )
            checker.assert_not_awaited()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE nodes SET name=?, metadata=? WHERE id=?",
                    ("node-kh", json.dumps({"role": "foreign", "node_name": "node-kh",
                                             "provisioning": "signed_checkin"}), self.node_id),
                )

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
