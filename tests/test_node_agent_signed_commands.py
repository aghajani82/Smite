"""Offline Agent HMAC guard integration tests.

Exercises FastAPI status/apply/remove and signed Panel payloads in a temp
SQLite replay store. Never sends requests to live IR/KH machines.
"""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "node"))
from app.config import settings
from app.agent_auth import DurableNonceStore, AgentAuthUnavailable
from app.replay_enrollment import provision_once
from app.routers.agent import router

spec = importlib.util.spec_from_file_location(
    "smite_panel_agent_request_signer", ROOT / "panel/app/agent_request_signer.py"
)
panel_signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel_signer)


class FakeAdapters:
    def __init__(self):
        self.active_tunnels = {}
        self.apply_calls = []
        self.remove_calls = []

    async def apply_tunnel(self, *, tunnel_id, tunnel_core, spec):
        self.apply_calls.append(tunnel_id)
        self.active_tunnels[tunnel_id] = (tunnel_core, spec)

    async def remove_tunnel(self, tunnel_id):
        self.remove_calls.append(tunnel_id)
        self.active_tunnels.pop(tunnel_id, None)

    async def get_tunnel_status(self, tunnel_id):
        return {"running": tunnel_id in self.active_tunnels}


class AgentGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        work = Path(self.tmp.name)
        ident_dir = work / "identity"
        replay_dir = work / "replay"
        ident_dir.mkdir(mode=0o700)
        replay_dir.mkdir(mode=0o700)
        self.ident = ident_dir / "node-identity.json"
        self.replay = replay_dir / "replay.sqlite3"
        self.node_id = "bbbbbbbb-1111-2222-3333-444444444444"
        self.secret = "b" * 64
        self.ident.write_text(json.dumps({
            "node_id": self.node_id, "node_secret": self.secret, "version": 1
        }))
        self.ident.chmod(0o600)
        provision_once(identity_path=self.ident, replay_path=self.replay)
        self.prior = (
            settings.smite_agent_auth_mode,
            settings.smite_agent_identity_path,
            settings.smite_agent_replay_db,
            settings.smite_engine_inventory_mode,
            settings.smite_engine_manifest_path,
        )
        settings.smite_agent_auth_mode = "strict"
        settings.smite_agent_identity_path = str(self.ident)
        settings.smite_agent_replay_db = str(self.replay)
        settings.smite_engine_inventory_mode = "legacy"
        settings.smite_engine_manifest_path = str(work / "engine-state" / "engines.json")
        self.addCleanup(self.restore)
        self.adapters = FakeAdapters()
        self.app = FastAPI()
        self.app.state.adapter_manager = self.adapters
        self.app.include_router(router, prefix="/api/agent")
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)

    def restore(self):
        (
            settings.smite_agent_auth_mode,
            settings.smite_agent_identity_path,
            settings.smite_agent_replay_db,
            settings.smite_engine_inventory_mode,
            settings.smite_engine_manifest_path,
        ) = self.prior

    def signed(self, method, target, *, payload=None, nonce=None, now=None, secret=None):
        return panel_signer.prepare_agent_request(
            secret=self.secret if secret is None else secret,
            node_id=self.node_id, method=method, target=target,
            payload=payload,
            timestamp=int(time.time()) if now is None else now,
            nonce=nonce,
        )


    def test_core_only_inventory_blocks_apply_even_with_valid_hmac(self):
        settings.smite_engine_inventory_mode = "managed"
        path = "/api/agent/engines"
        self.assertEqual(self.client.get(path).status_code, 401)
        body, headers = self.signed("GET", path, nonce="a" * 32)
        self.assertEqual(body, b"")
        inventory = self.client.get(path, headers=headers)
        self.assertEqual(inventory.status_code, 200, inventory.text)
        self.assertEqual(inventory.json()["mode"], "managed")
        self.assertTrue(all(state == "not-installed" for state in inventory.json()["engines"].values()))
        self.assertEqual(self.client.get(path, headers=headers).status_code, 401)

        for core in ("frp", "backhaul", "gost", "rathole", "chisel", "unrecognized"):
            payload = {"tunnel_id": "attempt-" + core, "core": core, "type": "tcp", "spec": {}}
            data, signature = self.signed("POST", "/api/agent/tunnels/apply", payload=payload)
            denied = self.client.post("/api/agent/tunnels/apply", content=data, headers=signature)
            self.assertEqual(denied.status_code, 409, (core, denied.text))
        self.assertEqual(self.adapters.apply_calls, [])

    def test_manifest_enrollment_requires_root_owned_sha_and_exact_binary(self):
        from unittest.mock import patch
        from app.engine_inventory import binary_path_for_engine
        settings.smite_engine_inventory_mode = "managed"
        location = Path(settings.smite_engine_manifest_path)
        location.parent.mkdir(mode=0o700)
        executable = location.parent / "verified-binary"
        executable.write_bytes(b"fixture binary without execution")
        executable.chmod(0o700)
        import hashlib
        valid_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
        location.write_text(json.dumps({
            "schema": 1, "engines": {"backhaul": {"sha256": valid_hash}}
        }))
        location.chmod(0o600)
        from app.engine_inventory import engine_inventory
        with patch("app.engine_inventory.binary_path_for_engine", return_value=executable):
            ready = engine_inventory()
            # The real production binary must be ROOT owned. CI fixtures are
            # runner owned, so patching the owner is not permitted; the
            # invalid fixture must stay unavailable.
            self.assertEqual(ready["engines"]["backhaul"], "unavailable")
            self.assertEqual(ready["engines"]["frp"], "not-installed")

            location.chmod(0o644)
            body, header = self.signed("GET", "/api/agent/engines")
            self.assertEqual(self.client.get("/api/agent/engines", headers=header).status_code, 503)
            location.chmod(0o600)
            executable.write_bytes(b"modified")
            self.assertEqual(engine_inventory()["engines"]["backhaul"], "unavailable")

    def test_legacy_mode_preserves_existing_apply_without_registry(self):
        from app.engine_inventory import engine_inventory
        self.assertEqual(engine_inventory()["mode"], "legacy")
        self.assertEqual(engine_inventory()["engines"]["frp"], "unmanaged")

    def test_legacy_defaults_unchanged_when_explicitly_selected(self):
        settings.smite_agent_auth_mode = "legacy"
        self.assertEqual(self.client.get("/api/agent/status").status_code, 200)
        self.assertEqual(self.client.post(
            "/api/agent/tunnels/apply",
            json={"tunnel_id": "one", "core": "frp", "type": "tcp", "spec": {}}
        ).status_code, 200)

    def test_every_agent_endpoint_requires_signature_in_strict_mode(self):
        self.assertEqual(self.client.get("/api/agent/status").status_code, 401)
        self.assertEqual(self.client.get("/api/agent/tunnels/status?tunnel_id=one").status_code, 401)
        self.assertEqual(self.client.post("/api/agent/tunnels/apply", json={
            "tunnel_id": "one", "core": "frp", "type": "tcp", "spec": {}
        }).status_code, 401)
        self.assertEqual(self.client.post("/api/agent/tunnels/remove", json={
            "tunnel_id": "one"
        }).status_code, 401)
        self.assertEqual(self.adapters.apply_calls, [])
        self.assertEqual(self.adapters.remove_calls, [])

    def test_signed_status_apply_remove_and_duplicate_rejected(self):
        body, headers = self.signed(
            "GET", "/api/agent/status", nonce="1" * 32
        )
        self.assertEqual(body, b"")
        self.assertEqual(self.client.get("/api/agent/status", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/agent/status", headers=headers).status_code, 401)

        data = {"tunnel_id": "signed", "core": "frp", "type": "tcp", "spec": {"local": 8081}}
        body, headers = self.signed("POST", "/api/agent/tunnels/apply", payload=data, nonce="2" * 32)
        reply = self.client.post("/api/agent/tunnels/apply", content=body, headers=headers)
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(self.adapters.apply_calls, ["signed"])
        self.assertEqual(self.client.post(
            "/api/agent/tunnels/apply", content=body, headers=headers
        ).status_code, 401)
        self.assertEqual(self.adapters.apply_calls, ["signed"])

        body, headers = self.signed("POST", "/api/agent/tunnels/remove",
                                    payload={"tunnel_id": "signed"}, nonce="3" * 32)
        self.assertEqual(self.client.post(
            "/api/agent/tunnels/remove", content=body, headers=headers
        ).status_code, 200)
        self.assertEqual(self.adapters.remove_calls, ["signed"])

    def test_wrong_key_and_payload_tamper_rejected_before_adapter(self):
        data = {"tunnel_id": "one", "core": "frp", "type": "tcp", "spec": {}}
        good, headers = self.signed("POST", "/api/agent/tunnels/apply", payload=data)
        self.assertEqual(self.client.post(
            "/api/agent/tunnels/apply", content=good + b" ", headers=headers
        ).status_code, 401)
        wrong, headers = self.signed("POST", "/api/agent/tunnels/apply", payload=data, secret="a" * 64)
        self.assertEqual(self.client.post(
            "/api/agent/tunnels/apply", content=wrong, headers=headers
        ).status_code, 401)
        self.assertEqual(self.adapters.apply_calls, [])

    def test_signed_exact_tunnel_status_query_and_tamper(self):
        path = "/api/agent/tunnels/status?tunnel_id=demo-123"
        body, headers = self.signed("GET", path, nonce="6" * 32)
        self.assertEqual(body, b"")
        # Trace the exact ASGI path used by the strict guard without
        # exposing credentials in CI logs.
        from app import agent_auth
        from unittest.mock import patch
        original = agent_auth.verify_agent_envelope
        seen = {}
        def capture(**kwargs):
            seen["target"] = kwargs["target"]
            seen["body_len"] = len(kwargs["body"])
            return original(**kwargs)
        with patch.object(agent_auth, "verify_agent_envelope", side_effect=capture):
            response = self.client.get(path, headers=headers)
        self.assertEqual(seen.get("target"), path, seen)
        self.assertEqual(seen.get("body_len"), 0, seen)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"], {"running": False})
        self.assertEqual(self.client.get(
            "/api/agent/tunnels/status?tunnel_id=demo-124", headers=headers
        ).status_code, 401)
        self.assertEqual(self.client.get(path, headers=headers).status_code, 401)

    def test_wrong_http_target_and_clock_skew_denied(self):
        body, headers = self.signed("GET", "/api/agent/status", nonce="4" * 32)
        self.assertEqual(self.client.get("/api/agent/status?x=1", headers=headers).status_code, 401)
        _, stale = self.signed(
            "GET", "/api/agent/status", nonce="5" * 32, now=int(time.time()) - 120
        )
        self.assertEqual(self.client.get("/api/agent/status", headers=stale).status_code, 401)

    def test_replay_store_survives_simulated_node_restart(self):
        body, headers = self.signed("GET", "/api/agent/status", nonce="7" * 32)
        self.assertEqual(self.client.get("/api/agent/status", headers=headers).status_code, 200)
        other = FastAPI()
        other.state.adapter_manager = FakeAdapters()
        other.include_router(router, prefix="/api/agent")
        with TestClient(other) as new_process:
            self.assertEqual(new_process.get(
                "/api/agent/status", headers=headers
            ).status_code, 401)
        self.assertEqual(self.replay.stat().st_mode & 0o777, 0o600)

    def test_file_permissions_or_missing_store_fail_closed(self):
        self.ident.chmod(0o644)
        self.assertEqual(self.client.get("/api/agent/status").status_code, 503)
        self.ident.chmod(0o600)
        self.replay.parent.chmod(0o755)
        body, headers = self.signed("GET", "/api/agent/status", nonce="8" * 32)
        self.assertEqual(self.client.get(
            "/api/agent/status", headers=headers
        ).status_code, 503)

    def test_replay_file_loss_never_silently_reinitializes(self):
        # First commit a real signed nonce to durable SQLite.
        body, headers = self.signed("GET", "/api/agent/status", nonce="e" * 32)
        self.assertEqual(self.client.get("/api/agent/status", headers=headers).status_code, 200)
        self.replay.unlink()
        self.assertFalse(self.replay.exists())
        # Even a perfectly signed request MUST fail closed (503).
        fresh, new_headers = self.signed("GET", "/api/agent/status", nonce="d" * 32)
        self.assertEqual(self.client.get("/api/agent/status", headers=new_headers).status_code, 503)
        # The original nonce cannot be given a new blank store.
        self.assertEqual(self.client.get("/api/agent/status", headers=headers).status_code, 503)
        self.assertFalse(self.replay.exists())
        # No request-side provisioning, even after a new FastAPI app.
        replacement = FastAPI()
        replacement.state.adapter_manager = FakeAdapters()
        replacement.include_router(router, prefix="/api/agent")
        with TestClient(replacement) as restarted:
            self.assertEqual(restarted.get("/api/agent/status", headers=new_headers).status_code, 503)
        self.assertFalse(self.replay.exists())

    def test_initialization_is_explicit_nonrepeatable_and_node_bound(self):
        with self.assertRaises(AgentAuthUnavailable):
            DurableNonceStore.initialize_new(self.replay, self.node_id)
        self.assertTrue(self.replay.exists())
        with self.assertRaises(AgentAuthUnavailable):
            DurableNonceStore(self.replay).register(
                "other-node-id", "a" * 32, int(time.time()))
        # The original enrollment remains usable after mismatched access.
        self.assertTrue(DurableNonceStore(self.replay).register(
            self.node_id, "b" * 32, int(time.time())))

    def test_empty_schema_and_symlinked_store_fail_closed(self):
        self.replay.unlink()
        self.replay.write_bytes(b"")
        self.replay.chmod(0o600)
        _, headers = self.signed("GET", "/api/agent/status", nonce="c" * 32)
        self.assertEqual(self.client.get("/api/agent/status", headers=headers).status_code, 503)
        self.replay.unlink()
        self.replay.symlink_to(self.ident)
        self.assertEqual(self.client.get("/api/agent/status", headers=headers).status_code, 503)

    def test_atomic_replay_under_parallel_attempts(self):
        store = DurableNonceStore(self.replay)
        outcomes = []
        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(
                lambda _: store.register(self.node_id, "f" * 32, int(time.time())),
                range(12)
            ))
        self.assertEqual(outcomes.count(True), 1)

    def test_signing_helper_rejects_outside_agent_targets(self):
        for path in ("http://node/api/agent/status", "/api/nodes", "/api/agent/status?x=1"):
            with self.subTest(path=path), self.assertRaises(panel_signer.AgentRequestPreparationError):
                self.signed("GET", path)
        with self.assertRaises(panel_signer.AgentRequestPreparationError):
            self.signed("GET", "/api/agent/status", payload={})


if __name__ == "__main__":
    unittest.main()
