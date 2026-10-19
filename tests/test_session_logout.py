"""Server-revoked JWT session logout: real FastAPI + disposable SQLite.

There are NO running Panel/Node services, Docker operations or VPS changes.
"""
import asyncio
from datetime import datetime
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from app.database import Base, get_db
from app.models import Admin
from app.routers import auth


class ServerSideLogout(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="smite-logout-ci-")
        self.addCleanup(self.tmp.cleanup)
        self.engine = create_async_engine(
            "sqlite+aiosqlite:///" + os.path.join(self.tmp.name, "panel.db")
        )
        self.maker = async_sessionmaker(self.engine, expire_on_commit=False)

        async def prepare():
            async with self.engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with self.maker() as session:
                session.add(Admin(
                    username="operator",
                    password_hash=auth.get_password_hash("local-test-password-strong"),
                    created_at=datetime.utcnow(),
                ))
                await session.commit()

        asyncio.run(prepare())

        async def db_override():
            async with self.maker() as session:
                yield session

        app = FastAPI()
        app.include_router(auth.router, prefix="/api/auth")
        app.dependency_overrides[get_db] = db_override
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.addCleanup(lambda: asyncio.run(self.engine.dispose()))

    def credentials(self):
        return {"username": "operator", "password": "local-test-password-strong"}

    def login(self):
        response = self.client.post("/api/auth/login", json=self.credentials())
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token):
        return {"Authorization": "Bearer " + token}

    def test_two_devices_revoked_atomically_then_fresh_login_works(self):
        first = self.login()
        second = self.login()
        for token in (first, second):
            self.assertEqual(
                self.client.get("/api/auth/me", headers=self.bearer(token)).status_code, 200
            )
        denied = self.client.post("/api/auth/logout")
        self.assertIn(denied.status_code, (401, 403))
        invalid = self.client.post(
            "/api/auth/logout", headers=self.bearer("invalid.invalid.invalid")
        )
        self.assertEqual(invalid.status_code, 401)

        out = self.client.post("/api/auth/logout", headers=self.bearer(first))
        self.assertEqual(out.status_code, 200, out.text)
        self.assertEqual(out.headers.get("Cache-Control"), "no-store")
        self.assertNotIn("access_token", out.text)
        self.assertEqual(out.json()["message"], "Signed out on all devices")

        for token in (first, second):
            self.assertEqual(
                self.client.get("/api/auth/me", headers=self.bearer(token)).status_code, 401
            )
            self.assertEqual(
                self.client.post("/api/auth/logout", headers=self.bearer(token)).status_code, 401
            )
        # All previous tokens are dead, even when generated at the same time.
        latest = self.login()
        self.assertEqual(self.client.get(
            "/api/auth/me", headers=self.bearer(latest)
        ).status_code, 200)

        async def version():
            async with self.maker() as session:
                user = (
                    await session.execute(select(Admin).where(Admin.username == "operator"))
                ).scalar_one()
                return user.auth_version

        self.assertEqual(asyncio.run(version()), 1)

    def test_mfa_required_sessions_cannot_bypass_authenticated_logout(self):
        # API cannot revoke sessions via forged JWT with no MFA claim.
        token = auth.create_access_token({"sub": "operator", "mfa": False, "v": 0})

        async def enable_test_mfa():
            async with self.maker() as session:
                user = (await session.execute(select(Admin).where(
                    Admin.username == "operator"
                ))).scalar_one()
                user.totp_secret = "encrypted-not-usable-ci-placeholder"
                await session.commit()

        asyncio.run(enable_test_mfa())
        self.assertEqual(self.client.post(
            "/api/auth/logout", headers=self.bearer(token)
        ).status_code, 401)
        qualified = auth.create_access_token({"sub": "operator", "mfa": True, "v": 0})
        self.assertEqual(self.client.post(
            "/api/auth/logout", headers=self.bearer(qualified)
        ).status_code, 200)
        self.assertEqual(self.client.get(
            "/api/auth/me", headers=self.bearer(qualified)
        ).status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
