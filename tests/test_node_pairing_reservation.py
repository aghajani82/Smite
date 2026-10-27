"""Offline admin-only role-bound signed Node reservation tests.

No production lifespan, sockets, live nodes, Docker, Nginx or VPS.
"""
import asyncio
import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest

from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))
from app.config import settings
from app.database import get_db
from app.models import Base
from app import node_pairing_store
from app.routers import auth, node_pairing


class ReservationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "test.db"
        self.engine = create_async_engine("sqlite+aiosqlite:///" + str(self.path))
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)

        async def init():
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

        asyncio.run(init())
        node_pairing_store.initialize_schema(self.path)
        self.old = (
            settings.db_path, settings.smite_node_pairing_preview_enabled,
            settings.smite_node_pairing_master_key,
            settings.smite_node_pairing_ingress_token,
            settings.smite_node_registration_mode,
            settings.smite_panel_agent_auth_mode,
        )
        settings.db_path = str(self.path)
        settings.smite_node_pairing_preview_enabled = False
        settings.smite_node_pairing_master_key = Fernet.generate_key().decode()
        settings.smite_node_pairing_ingress_token = "ingress-" + "a" * 32
        settings.smite_node_registration_mode = "signed"
        settings.smite_panel_agent_auth_mode = "signed"

        self.app = FastAPI()
        self.app.include_router(node_pairing.router, prefix="/api/node-pairing")
        async def isolated_db():
            async with self.sessions() as session:
                yield session
        self.app.dependency_overrides[get_db] = isolated_db
        self.client = TestClient(self.app)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.client.close()
        asyncio.run(self.engine.dispose())
        (settings.db_path, settings.smite_node_pairing_preview_enabled,
         settings.smite_node_pairing_master_key,
         settings.smite_node_pairing_ingress_token,
         settings.smite_node_registration_mode,
         settings.smite_panel_agent_auth_mode) = self.old
        self.tmp.cleanup()

    def admin(self):
        self.app.dependency_overrides[auth.get_current_user] = lambda: SimpleNamespace(id="admin-test")

    def reserve(self, name="node-kh-01", role="foreign"):
        return self.client.post("/api/node-pairing/reserve", json={"name": name, "role": role})

    def test_anonymous_denied_and_disabled_preview_stays_inert(self):
        self.assertIn(self.reserve().status_code, (401, 403))
        self.admin()
        resp = self.reserve()
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.headers["cache-control"], "no-store")
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM nodes").fetchone()[0], 0)

    def test_reservation_then_one_time_issue_without_legacy_registration(self):
        self.admin()
        settings.smite_node_pairing_preview_enabled = True
        resp = self.reserve()
        self.assertEqual(resp.status_code, 201, resp.text)
        self.assertEqual(resp.headers["cache-control"], "no-store")
        data = resp.json()
        self.assertEqual(set(data), {"node_id", "name", "status"})
        self.assertEqual(data["name"], "node-kh-01")
        self.assertEqual(data["status"], "pending")
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT status, fingerprint, metadata FROM nodes WHERE id=?", (data["node_id"],)).fetchone()
            self.assertEqual(row[0], "pending")
            self.assertTrue(row[1].startswith("reserved-"))
            self.assertEqual(json.loads(row[2]), {
                "role": "foreign", "node_name": "node-kh-01", "provisioning": "reserved_for_pairing"
            })
        self.assertEqual(self.reserve().status_code, 409)
        issued = self.client.post("/api/node-pairing/issue", json={
            "node_id": data["node_id"], "role": "foreign", "ttl_seconds": 600
        })
        self.assertEqual(issued.status_code, 200, issued.text)
        self.assertTrue(issued.json()["pairing_code"].startswith("smn1_"))
        self.assertNotIn("node_secret", issued.text)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM nodes").fetchone()[0], 1)

    def test_iran_and_foreign_roles_are_immutable_in_pending_reservation(self):
        self.admin()
        settings.smite_node_pairing_preview_enabled = True
        for role, name in (("iran", "node-ir-01"), ("foreign", "node-kh-02")):
            with self.subTest(role=role):
                response = self.reserve(name=name, role=role)
                self.assertEqual(response.status_code, 201, response.text)
                node_id = response.json()["node_id"]
                with sqlite3.connect(self.path) as db:
                    row = db.execute(
                        "SELECT status, metadata FROM nodes WHERE id=?", (node_id,)
                    ).fetchone()
                self.assertEqual(row[0], "pending")
                self.assertEqual(json.loads(row[1]), {
                    "role": role,
                    "node_name": name,
                    "provisioning": "reserved_for_pairing",
                })
                issued = self.client.post("/api/node-pairing/issue", json={
                    "node_id": node_id, "role": role, "ttl_seconds": 600,
                })
                self.assertEqual(issued.status_code, 200, issued.text)
                mismatched = self.client.post("/api/node-pairing/issue", json={
                    "node_id": node_id,
                    "role": "foreign" if role == "iran" else "iran",
                    "ttl_seconds": 600,
                })
                self.assertEqual(mismatched.status_code, 409)

    def test_invalid_role_and_non_signed_registration_fail_closed(self):
        self.admin()
        settings.smite_node_pairing_preview_enabled = True
        for role in ("", "IR", "other", "Iran", "foreign-admin"):
            with self.subTest(role=role):
                self.assertEqual(self.reserve(name="role-invalid", role=role).status_code, 422)
        settings.smite_node_registration_mode = "legacy"
        self.assertEqual(self.reserve().status_code, 503)
        settings.smite_node_registration_mode = "signed"
        settings.smite_panel_agent_auth_mode = "legacy"
        self.assertEqual(self.reserve().status_code, 503)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM nodes").fetchone()[0], 0)

    def test_invalid_names_and_missing_schema_fail_closed(self):
        self.admin()
        settings.smite_node_pairing_preview_enabled = True
        for name in ("", " ", "bad/name", "bad name", "a", "../escape", "x" * 65):
            with self.subTest(name=name):
                self.assertEqual(self.reserve(name).status_code, 422)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE smite_node_identities")
        self.assertEqual(self.reserve().status_code, 503)

    def test_bad_master_key_rejects_reservation(self):
        self.admin()
        settings.smite_node_pairing_preview_enabled = True
        settings.smite_node_pairing_master_key = "changeme"
        self.assertEqual(self.reserve().status_code, 503)


if __name__ == "__main__":
    unittest.main()
