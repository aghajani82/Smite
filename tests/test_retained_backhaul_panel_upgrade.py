"""Exercise the old and new Panel against the same disposable RC9 database."""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal, engine, init_db
from app.models import Node, Tunnel


PORTS = {"frp-a": 32868, "backhaul-a": 38463, "backhaul-b": 31402}


async def verify_rows():
    async with AsyncSessionLocal() as db:
        rows = (await db.scalars(select(Tunnel))).all()
        assert {(row.id, row.spec["data_port"], row.status, row.revision)
                for row in rows} == {(name, port, "active", 7)
                                     for name, port in PORTS.items()}
        nodes = (await db.scalars(select(Node))).all()
        assert {row.id: row.fingerprint for row in nodes} == {
            "test-iran": "iran-key", "test-foreign": "foreign-key",
        }


async def check(mode):
    await init_db()
    try:
        if mode == "prepare":
            async with AsyncSessionLocal() as db:
                for role in ("iran", "foreign"):
                    db.add(Node(id="test-" + role, name=role, fingerprint=role + "-key",
                                node_metadata={"role": role, "ip_address": "192.0.2.1",
                                               "api_address": "http://192.0.2.1:8888"}))
                for name, port in PORTS.items():
                    core = name.rsplit("-", 1)[0]
                    spec = {"data_port": port}
                    if core == "backhaul":
                        spec.update(uopti_standard_backhaul=True, control_port=3080,
                                    ports=[f"127.0.0.1:{port}=127.0.0.1:{port}"])
                    db.add(Tunnel(id=name, name=name, core=core, type="ws", node_id="test-iran",
                                  iran_node_id="test-iran", foreign_node_id="test-foreign",
                                  spec=spec, status="active", revision=7))
                await db.commit()
        elif mode == "candidate":
            from app.models import BackhaulPublishRequest
            from main import _restore_node_tunnels

            outbound = AsyncMock(side_effect=AssertionError("unexpected signed Node command"))
            assert settings.smite_panel_agent_auth_mode == "signed"
            assert settings.smite_engine_management_mode == "managed"
            with patch("main.NodeClient.send_to_node", outbound):
                await _restore_node_tunnels()
            outbound.assert_not_awaited()
            async with AsyncSessionLocal() as db:
                db.add(BackhaulPublishRequest(id="third-backhaul", name="Third Backhaul",
                                             iran_node_id="test-iran", foreign_node_id="test-foreign",
                                             port=56053, status="queued"))
                await db.commit()
        elif mode != "rollback":
            raise ValueError("Unknown test step")
        await verify_rows()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    # Require an unused test database for the first step and an existing
    # disposable test database for all subsequent steps.
    mode = sys.argv[1]
    database = Path(settings.db_path)
    assert database.name == "retained-backhaul-fixture.sqlite3"
    assert database.is_file() == (mode != "prepare")
    asyncio.run(check(mode))
