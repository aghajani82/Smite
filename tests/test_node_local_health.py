"""Node Docker healthcheck must work in strict auth WITHOUT weakening Agent.

No servers, sockets, Docker containers or files are modified by this test.
"""
import asyncio
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace

from fastapi import HTTPException, Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "node"))
from app.routers.local_health import local_health


def req(peer: str | None, *, ready: bool = True, forwarded: str | None = None):
    app = SimpleNamespace(state=SimpleNamespace())
    if ready:
        app.state.adapter_manager = SimpleNamespace(active_tunnels={})
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request({
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/healthz",
        "raw_path": b"/healthz",
        "query_string": b"",
        "headers": headers,
        "client": (peer, 12345) if peer is not None else None,
        "server": ("127.0.0.1", 8888),
        "app": app,
    })


class NodeHealthTest(unittest.TestCase):
    def test_loopback_ready_returns_minimal_result(self):
        self.assertEqual(asyncio.run(local_health(req("127.0.0.1"))), {"status": "ok"})
        self.assertEqual(asyncio.run(local_health(req("::1"))), {"status": "ok"})

    def test_not_yet_initialized_is_not_healthy(self):
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(local_health(req("127.0.0.1", ready=False)))
        self.assertEqual(cm.exception.status_code, 503)

    def test_remote_address_denied_even_with_loopback_forwarded_header(self):
        for client in ("192.0.2.25", "10.0.0.25", "testclient", None):
            with self.subTest(client=client):
                with self.assertRaises(HTTPException) as cm:
                    asyncio.run(local_health(req(client, forwarded="127.0.0.1")))
                self.assertEqual(cm.exception.status_code, 403)

    def test_minimal_liveness_contains_no_inventory_or_identity(self):
        result = asyncio.run(local_health(req("127.0.0.1")))
        self.assertEqual(set(result), {"status"})
        self.assertNotIn("tunnels", str(result))
        self.assertNotIn("secret", str(result))
        self.assertNotIn("engines", str(result))

    def test_compose_health_target_and_agent_auth_boundary(self):
        compose = (ROOT / "node/docker-compose.yml").read_text()
        main = (ROOT / "node/main.py").read_text()
        agent = (ROOT / "node/app/routers/agent.py").read_text()
        self.assertIn("http://127.0.0.1:${NODE_API_PORT:-8888}/healthz", compose)
        self.assertNotIn("/api/agent/status", compose)
        self.assertIn("app.include_router(local_health.router)", main)
        self.assertIn("APIRouter(dependencies=[Depends(require_agent_auth)])", agent)
        self.assertIn("include_in_schema=False", (ROOT / "node/app/routers/local_health.py").read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
