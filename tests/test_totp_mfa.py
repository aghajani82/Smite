"""Real MFA integration and RFC 6238 regression tests; no Panel or Node services."""
import asyncio
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select

from app.database import Base, get_db
from app.models import Admin
from app.routers import auth
from app import mfa


class TotpMfaContract(unittest.TestCase):
    def test_rfc_6238_known_vector(self):
        # RFC 6238 test vector at T=59, 8 digit value 94287082; 6 digits suffix.
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(mfa.totp(secret, 1), "287082")
        self.assertEqual(mfa.matching_step(secret, "287082", now=59), 1)
        self.assertIsNone(mfa.matching_step(secret, "287082", last_step=1, now=59))
        self.assertIsNone(mfa.matching_step(secret, "2870820", now=59))

    def test_random_recovery_codes_are_unique(self):
        codes = mfa.create_recovery_codes()
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)
        self.assertTrue(all(len(code.replace("-", "")) == 20 for code in codes))


class TwoFactorEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_secret = mfa.settings.secret_key
        mfa.settings.secret_key = "integration-test-secret-key-not-for-production-1234567890"
        cls.tmp = tempfile.TemporaryDirectory(prefix="smite-mfa-test-")
        cls.engine = create_async_engine("sqlite+aiosqlite:///" + os.path.join(cls.tmp.name, "mfa.db"))
        cls.maker = async_sessionmaker(cls.engine, expire_on_commit=False)

        async def prepare():
            async with cls.engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with cls.maker() as session:
                session.add(Admin(username="operator", password_hash=auth.get_password_hash("password-strong-test"), created_at=datetime.utcnow()))
                await session.commit()
        asyncio.run(prepare())

        async def db_override():
            async with cls.maker() as session:
                yield session

        cls.app = FastAPI()
        cls.app.include_router(auth.router, prefix="/api/auth")
        cls.app.dependency_overrides[get_db] = db_override
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        asyncio.run(cls.engine.dispose())
        cls.tmp.cleanup()
        mfa.settings.secret_key = cls.old_secret

    def test_full_two_factor_flow(self):
        def log_in(extra=None):
            data = {"username": "operator", "password": "password-strong-test"}
            if extra:
                data.update(extra)
            return self.client.post("/api/auth/login", json=data)

        first = log_in()
        self.assertEqual(first.status_code, 200, first.text)
        old_token = first.json()["access_token"]
        headers = {"Authorization": "Bearer " + old_token}
        self.assertEqual(self.client.get("/api/auth/2fa/status", headers=headers).json()["enabled"], False)

        no_password = self.client.post("/api/auth/2fa/setup", headers=headers, json={"password": "wrong"})
        self.assertEqual(no_password.status_code, 401)
        setup = self.client.post("/api/auth/2fa/setup", headers=headers, json={"password": "password-strong-test"})
        self.assertEqual(setup.status_code, 200, setup.text)
        secret = setup.json()["secret"]
        self.assertIn("otpauth://totp/", setup.json()["otpauth_uri"])
        self.assertNotIn(secret, str(setup.headers))
        bad_enable = self.client.post("/api/auth/2fa/enable", headers=headers, json={"password": "password-strong-test", "code": "0000000"})
        self.assertEqual(bad_enable.status_code, 400)

        good_code = mfa.totp(secret, int(__import__("time").time()) // 30)
        enabled = self.client.post("/api/auth/2fa/enable", headers=headers, json={"password": "password-strong-test", "code": good_code})
        self.assertEqual(enabled.status_code, 200, enabled.text)
        data = enabled.json()
        self.assertEqual(len(data["recovery_codes"]), 10)
        new_headers = {"Authorization": "Bearer " + data["access_token"]}
        self.assertTrue(self.client.get("/api/auth/2fa/status", headers=new_headers).json()["enabled"])
        self.assertEqual(self.client.get("/api/auth/2fa/status", headers=headers).status_code, 401)

        self.assertEqual(log_in().status_code, 428)
        self.assertEqual(log_in({"mfa_code": "9999999"}).status_code, 401)
        self.assertEqual(log_in({"mfa_code": good_code}).status_code, 401)  # replay
        recovery = data["recovery_codes"]
        self.assertEqual(log_in({"mfa_code": recovery[0]}).status_code, 200)
        self.assertEqual(log_in({"mfa_code": recovery[0]}).status_code, 401)

        async def inspect():
            async with self.maker() as session:
                admin = (await session.execute(select(Admin).where(Admin.username == "operator"))).scalar_one()
                return admin.totp_secret, admin.recovery_codes, admin.auth_version
        sealed, hashed, version = asyncio.run(inspect())
        self.assertNotIn(secret, sealed)
        self.assertEqual(len(hashed), 9)
        self.assertEqual(version, 1)

        disable = self.client.post(
            "/api/auth/2fa/disable",
            headers=new_headers,
            json={"password": "password-strong-test", "code": recovery[1]},
        )
        self.assertEqual(disable.status_code, 200, disable.text)
        self.assertEqual(self.client.get("/api/auth/2fa/status", headers=new_headers).status_code, 401)
        self.assertEqual(log_in().status_code, 200)


if __name__ == "__main__":
    unittest.main()
