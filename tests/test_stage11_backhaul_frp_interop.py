"""Stage 11: offline Standard Backhaul + FRP/443 integration regression tests.

No Docker, tunnels, network or live service modification.
"""
import asyncio
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))
from app.uopti_backhaul_dispatch import compile_dispatch_payload
from app.uopti_backhaul_lifecycle import require_managed_backhaul_activation
from app.uopti_backhaul_standard import (
    compile_standard_specs, normalize_node_spec, StandardBackhaulSpecError,
)
from app.node_client import NodeClient
from app.config import settings as panel_settings

NODE_MODULE = ROOT / "node/app/uopti_backhaul_standard.py"
FRP_HELPER = ROOT / "node/app/frp_gateway_config.py"


def isolated(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


node_backhaul = isolated(NODE_MODULE, "node_backhaul_spec")
frp = isolated(FRP_HELPER, "frp_gateway_config_stage11")

CANONICAL = {
    "uopti_standard_backhaul": True,
    "token": "EXAMPLE-UNIT-TEST-TOKEN-12345678901234",
    "transport": "ws",
    "type": "ws",
    "ports": ["127.0.0.1:56053=127.0.0.1:56053"],
    "data_port": 56053,
    "control_port": 3080,
    "bridge_port": 13080,
}


class BackhaulSignedDispatchTest(unittest.IsolatedAsyncioTestCase):
    def test_compilers_are_identical_and_preserve_loopback(self):
        self.assertEqual(
            (ROOT / "panel/app/uopti_backhaul_standard.py").read_bytes(),
            NODE_MODULE.read_bytes(),
        )
        server, client = compile_standard_specs(CANONICAL)
        self.assertEqual(server["mode"], "server")
        self.assertEqual(client["mode"], "client")
        self.assertEqual(server["bind_addr"], "127.0.0.1:3080")
        self.assertEqual(client["remote_addr"], "127.0.0.1:13080")
        self.assertEqual(server["ports"], ["127.0.0.1:56053=127.0.0.1:56053"])
        self.assertEqual(node_backhaul.normalize_node_spec(server), server)
        self.assertEqual(node_backhaul.normalize_node_spec(client), client)

    def test_signed_and_legacy_dispatch_prepare_same_persisted_spec(self):
        original = {
            "tunnel_id": "tunnel-01", "core": "backhaul",
            "type": "ws", "spec": {"token": "IGNORED-ATTACKER-VALUE"}
        }
        iran = compile_dispatch_payload(
            node_role="iran", stored_spec=CANONICAL,
            endpoint="/api/agent/tunnels/apply", incoming=original,
        )
        foreign = compile_dispatch_payload(
            node_role="foreign", stored_spec=CANONICAL,
            endpoint="/api/agent/tunnels/apply", incoming=original,
        )
        self.assertEqual(iran["spec"]["mode"], "server")
        self.assertEqual(foreign["spec"]["mode"], "client")
        self.assertEqual(iran["spec"]["token"], CANONICAL["token"])
        self.assertEqual(original["spec"]["token"], "IGNORED-ATTACKER-VALUE")
        self.assertEqual(foreign["spec"]["remote_addr"], "127.0.0.1:13080")

    def test_flag_requires_persisted_approval_and_valid_role(self):
        request = {
            "core": "backhaul", "spec": {"uopti_standard_backhaul": True},
        }
        with self.assertRaises(StandardBackhaulSpecError):
            compile_dispatch_payload(
                node_role="foreign", stored_spec={},
                endpoint="/api/agent/tunnels/apply", incoming=request,
            )
        with self.assertRaises(StandardBackhaulSpecError):
            compile_dispatch_payload(
                node_role="unknown", stored_spec=CANONICAL,
                endpoint="/api/agent/tunnels/apply", incoming=request,
            )
        bad = dict(CANONICAL, bind_ip="0.0.0.0")
        with self.assertRaises(StandardBackhaulSpecError):
            compile_dispatch_payload(
                node_role="iran", stored_spec=bad,
                endpoint="/api/agent/tunnels/apply", incoming=request,
            )

    def test_managed_panel_and_dispatch_refuse_unapproved_backhaul(self):
        unsafe = {"transport": "tcp", "bind_addr": "0.0.0.0:3080"}
        with self.assertRaises(StandardBackhaulSpecError):
            require_managed_backhaul_activation(
                core="backhaul", spec=unsafe, management_mode="managed",
            )
        with self.assertRaises(StandardBackhaulSpecError):
            compile_dispatch_payload(
                node_role="iran", stored_spec=unsafe, management_mode="managed",
                endpoint="/api/agent/tunnels/apply",
                incoming={"core": "backhaul", "spec": unsafe},
            )
        # The same explicit canonical persisted spec remains eligible for
        # signed dispatch, but real transport/443 is a separate release gate.
        require_managed_backhaul_activation(
            core="backhaul", spec=CANONICAL, management_mode="managed",
        )
        result = compile_dispatch_payload(
            node_role="foreign", stored_spec=CANONICAL,
            management_mode="managed", endpoint="/api/agent/tunnels/apply",
            incoming={"core": "backhaul", "spec": unsafe},
        )
        self.assertEqual(result["spec"]["remote_addr"], "127.0.0.1:13080")
        # No collateral restrictions on FRP or legacy Stable Backhaul.
        require_managed_backhaul_activation(
            core="frp", spec=unsafe, management_mode="managed",
        )
        require_managed_backhaul_activation(
            core="backhaul", spec=unsafe, management_mode="legacy",
        )

    def test_managed_standard_rejects_wildcard_and_bad_token(self):
        for invalid in (
            dict(CANONICAL, bind_ip="0.0.0.0"),
            dict(CANONICAL, transport="tcp"),
            dict(CANONICAL, token="too-short"),
            dict(CANONICAL, ports=["443=127.0.0.1:443"]),
            dict(CANONICAL, remote_addr="example.org:443"),
        ):
            with self.subTest(invalid=list(invalid.keys())):
                with self.assertRaises(StandardBackhaulSpecError):
                    require_managed_backhaul_activation(
                        core="backhaul", spec=invalid,
                        management_mode="managed",
                    )

    def test_frp_and_regular_backhaul_passthrough(self):
        request = {"core": "frp", "spec": {"client": True}}
        self.assertIs(
            compile_dispatch_payload(
                node_role=None, stored_spec=None,
                endpoint="/api/agent/tunnels/apply", incoming=request,
            ), request
        )
        existing = {"core": "backhaul", "spec": {"transport": "tcp"}}
        self.assertIs(
            compile_dispatch_payload(
                node_role="iran", stored_spec={},
                endpoint="/api/agent/tunnels/apply", incoming=existing,
            ), existing
        )

    async def test_actual_nodeclient_signed_path_receives_normalized_payload(self):
        client = NodeClient()
        original = panel_settings.smite_panel_agent_auth_mode
        panel_settings.smite_panel_agent_auth_mode = "signed"
        self.addCleanup(setattr, panel_settings, "smite_panel_agent_auth_mode", original)
        standardized = {
            "core": "backhaul", "tunnel_id": "t1",
            "spec": {"mode": "client", "uopti_standard_backhaul": True}
        }
        with patch("app.node_client.prepare_node_command",
                   new_callable=AsyncMock, return_value=standardized) as prepare:
            with patch.object(client, "_signed_agent_request",
                              new_callable=AsyncMock, return_value={"status": "ok"}) as signed:
                result = await client.send_to_node(
                    "node-abcd1234", "/api/agent/tunnels/apply",
                    {"core": "backhaul", "tunnel_id": "t1", "spec": {}},
                )
                self.assertEqual(result, {"status": "ok"})
                prepare.assert_awaited_once()
                self.assertEqual(
                    signed.await_args.kwargs["payload"], standardized
                )

    async def test_invalid_standard_never_calls_signed_transport(self):
        client = NodeClient()
        original = panel_settings.smite_panel_agent_auth_mode
        panel_settings.smite_panel_agent_auth_mode = "signed"
        self.addCleanup(setattr, panel_settings, "smite_panel_agent_auth_mode", original)
        with patch("app.node_client.prepare_node_command",
                   new_callable=AsyncMock, side_effect=StandardBackhaulSpecError("bad")):
            with patch.object(client, "_signed_agent_request", new_callable=AsyncMock) as signed:
                reply = await client.send_to_node(
                    "node-abcd1234", "/api/agent/tunnels/apply",
                    {"core": "backhaul", "spec": {}},
                )
                self.assertEqual(reply["status"], "error")
                signed.assert_not_awaited()


    async def test_managed_backhaul_create_does_not_auto_apply_only_iran(self):
        # This exercises the actual Panel Create handler with a fake database.
        # Signed engines can report ready, but a newly persisted Backhaul
        # must NOT run only the IR half or be marked active prematurely.
        from types import SimpleNamespace
        from app.routers import tunnels as routes

        class Result:
            def __init__(self, row):
                self.row = row

            def scalar_one_or_none(self):
                return self.row

        class FakeDB:
            def __init__(self):
                self.nodes = [
                    SimpleNamespace(id="foreign-ci", node_metadata={"role": "foreign"}),
                    SimpleNamespace(id="iran-ci", node_metadata={"role": "iran"}),
                ]
                self.created = None
                self.commits = 0

            async def execute(self, statement):
                return Result(self.nodes.pop(0))

            def add(self, row):
                self.created = row

            async def commit(self):
                self.commits += 1

            async def refresh(self, row):
                if row.id is None:
                    row.id = "backhaul-ci-new-id"

        request = SimpleNamespace(
            name="CI approved Backhaul", core="backhaul", type="ws",
            node_id="iran-ci", iran_node_id="iran-ci",
            foreign_node_id="foreign-ci", spec=CANONICAL.copy(),
        )
        db = FakeDB()
        with patch.object(panel_settings, "smite_engine_management_mode", "managed"):
            with patch.object(routes, "require_engine_ready_pair",
                              new_callable=AsyncMock) as admitted:
                with patch("app.node_client.NodeClient.send_to_node",
                           new_callable=AsyncMock) as node_apply:
                    saved = await routes.create_tunnel(
                        request, SimpleNamespace(), db)
        admitted.assert_awaited_once()
        node_apply.assert_not_awaited()
        self.assertIs(saved, db.created)
        self.assertEqual(saved.status, "pending")
        self.assertEqual(db.commits, 1)
        self.assertEqual(db.nodes, [])
        self.assertEqual(saved.spec, CANONICAL)


class BackhaulPairCompensationTest(unittest.IsolatedAsyncioTestCase):
    """No live Node or network: signed Apply/Remove/status are fake endpoints."""

    def setUp(self):
        from types import SimpleNamespace
        self.tunnel = SimpleNamespace(
            id="ci-bh-new-uuid", core="backhaul", type="ws",
            status="pending", error_message=None, spec=CANONICAL.copy(),
            iran_node_id="ci-ir", foreign_node_id="ci-foreign",
            node_id="ci-ir",
        )
        self.current = {"ci-ir": False, "ci-foreign": False}
        self.saved = {"ci-ir": False, "ci-foreign": False}
        self.actions = []
        self.db = SimpleNamespace(
            execute=AsyncMock(return_value=SimpleNamespace(rowcount=1)),
            commit=AsyncMock(), rollback=AsyncMock(),
        )
        self.client = SimpleNamespace(
            _signed_agent_request=AsyncMock(side_effect=self.status),
            send_to_node=AsyncMock(side_effect=self.command),
        )
        self.mode = patch.object(panel_settings, "smite_engine_management_mode", "managed")
        self.auth = patch.object(panel_settings, "smite_panel_agent_auth_mode", "signed")
        self.mode.start()
        self.auth.start()
        self.addCleanup(self.mode.stop)
        self.addCleanup(self.auth.stop)

    async def status(self, node_id, *, method, target, timeout):
        self.assertEqual(method, "GET")
        self.assertEqual(timeout, 3.0)
        self.assertEqual(target,
                         "/api/agent/tunnels/status?tunnel_id=ci-bh-new-uuid")
        active, present = self.current[node_id], self.saved[node_id]
        return {"status": "success",
                "data": {"active": active, "record_present": present,
                         "record_core": "backhaul" if present else None,
                         **({"type": "backhaul"} if active else {})}}

    async def command(self, *, node_id, endpoint, data):
        self.actions.append((node_id, endpoint))
        self.assertEqual(data["tunnel_id"], self.tunnel.id)
        if endpoint.endswith("/apply"):
            self.assertEqual(data["core"], "backhaul")
            self.current[node_id] = True
            self.saved[node_id] = True
        else:
            self.assertEqual(data, {"tunnel_id": self.tunnel.id})
            self.current[node_id] = False
            self.saved[node_id] = False
        return {"status": "success"}

    async def run_pair(self):
        from app.uopti_backhaul_lifecycle import apply_managed_backhaul_pair
        return await apply_managed_backhaul_pair(
            tunnel=self.tunnel, iran_node_id="ci-ir",
            foreign_node_id="ci-foreign", client=self.client, db=self.db)

    async def test_complete_signed_pair_only_after_both_running(self):
        out = await self.run_pair()
        self.assertEqual(out["status"], "applied")
        self.assertEqual(self.tunnel.status, "active")
        self.assertEqual(self.tunnel.spec, CANONICAL)
        self.assertEqual(self.current, {"ci-ir": True, "ci-foreign": True})
        self.assertEqual(self.actions, [
            ("ci-ir", "/api/agent/tunnels/apply"),
            ("ci-foreign", "/api/agent/tunnels/apply"),
        ])
        self.assertEqual(self.db.commit.await_count, 2)

    async def test_foreign_reject_compensates_ir_only(self):
        from app.uopti_backhaul_lifecycle import ManagedBackhaulPairHold
        async def fail_foreign(*, node_id, endpoint, data):
            if node_id == "ci-foreign" and endpoint.endswith("/apply"):
                self.actions.append((node_id, endpoint))
                return {"status": "error", "message": "REDACTED"}
            return await self.command(node_id=node_id, endpoint=endpoint, data=data)
        self.client.send_to_node.side_effect = fail_foreign
        with self.assertRaisesRegex(ManagedBackhaulPairHold,
                                    "BACKHAUL_PAIR_ROLLED_BACK"):
            await self.run_pair()
        self.assertEqual(self.current, {"ci-ir": False, "ci-foreign": False})
        self.assertEqual(self.actions, [
            ("ci-ir", "/api/agent/tunnels/apply"),
            ("ci-foreign", "/api/agent/tunnels/apply"),
            ("ci-ir", "/api/agent/tunnels/remove"),
        ])
        # Signed persisted-state proof establishes Foreign had no durable
        # record; IR was compensated, so it is now safe to retry manually.
        self.assertEqual(self.tunnel.status, "pending")
        self.assertNotIn("REDACTED", self.tunnel.error_message)

    async def test_timeout_after_foreign_apply_compensates_both(self):
        from app.uopti_backhaul_lifecycle import ManagedBackhaulPairHold
        async def timeout_after_apply(*, node_id, endpoint, data):
            result = await self.command(
                node_id=node_id, endpoint=endpoint, data=data)
            if node_id == "ci-foreign" and endpoint.endswith("/apply"):
                raise TimeoutError("unknown after commit")
            return result
        self.client.send_to_node.side_effect = timeout_after_apply
        with self.assertRaises(ManagedBackhaulPairHold):
            await self.run_pair()
        self.assertEqual(self.current, {"ci-ir": False, "ci-foreign": False})
        self.assertEqual(self.saved, {"ci-ir": False, "ci-foreign": False})
        self.assertEqual(self.actions[-2:], [
            ("ci-foreign", "/api/agent/tunnels/remove"),
            ("ci-ir", "/api/agent/tunnels/remove"),
        ])
        self.assertEqual(self.tunnel.status, "pending")

    async def test_acknowledged_apply_with_dead_process_removes_saved_id(self):
        from app.uopti_backhaul_lifecycle import ManagedBackhaulPairHold
        calls = {"iran": 0}
        async def stop_ir_after_ack(node_id, *, method, target, timeout):
            if node_id == "ci-ir":
                calls["iran"] += 1
                if calls["iran"] > 1:
                    self.current[node_id] = False
            return await self.status(node_id, method=method,
                                     target=target, timeout=timeout)
        self.client._signed_agent_request.side_effect = stop_ir_after_ack
        with self.assertRaisesRegex(ManagedBackhaulPairHold,
                                    "BACKHAUL_PAIR_ROLLED_BACK"):
            await self.run_pair()
        self.assertIn(("ci-ir", "/api/agent/tunnels/remove"), self.actions)
        self.assertEqual(self.tunnel.status, "pending")

    async def test_rollback_unknown_quarantines_without_auto_retry(self):
        from app.uopti_backhaul_lifecycle import ManagedBackhaulPairHold
        calls = {"foreign": 0}
        async def fail_foreign_status(node_id, *, method, target, timeout):
            if node_id == "ci-foreign":
                calls["foreign"] += 1
                if calls["foreign"] > 1:
                    return {"status": "error", "message": "host unavailable"}
            return await self.status(node_id, method=method,
                                     target=target, timeout=timeout)
        async def fail_foreign_apply(*, node_id, endpoint, data):
            if node_id == "ci-foreign" and endpoint.endswith("/apply"):
                raise TimeoutError("possibly already applied")
            return await self.command(node_id=node_id, endpoint=endpoint, data=data)
        self.client._signed_agent_request.side_effect = fail_foreign_status
        self.client.send_to_node.side_effect = fail_foreign_apply
        with self.assertRaisesRegex(ManagedBackhaulPairHold,
                                    "BACKHAUL_PAIR_RECOVERY_REQUIRED"):
            await self.run_pair()
        self.assertEqual(self.tunnel.status, "error")
        self.assertEqual(self.tunnel.error_message, "BACKHAUL_PAIR_RECOVERY_REQUIRED")
        self.assertFalse(self.current["ci-ir"])
        self.assertNotIn(("ci-foreign", "/api/agent/tunnels/remove"), self.actions)
        with self.assertRaisesRegex(ManagedBackhaulPairHold,
                                    "BACKHAUL_PAIR_PENDING_SIGNED_REQUIRED"):
            await self.run_pair()

    async def test_dormant_frp_record_denies_before_any_apply_or_removal(self):
        from app.uopti_backhaul_lifecycle import ManagedBackhaulPairHold
        self.saved["ci-foreign"] = True
        async def dormant_frp(node_id, *, method, target, timeout):
            reply = await self.status(node_id, method=method,
                                      target=target, timeout=timeout)
            if node_id == "ci-foreign":
                reply["data"]["record_core"] = "frp"
            return reply
        self.client._signed_agent_request.side_effect = dormant_frp
        with self.assertRaisesRegex(ManagedBackhaulPairHold,
                                    "BACKHAUL_PAIR_ALREADY_PRESENT"):
            await self.run_pair()
        self.client.send_to_node.assert_not_awaited()
        self.assertEqual(self.tunnel.status, "pending")
        self.db.execute.assert_not_awaited()

    async def test_dormant_backhaul_record_denies_preflight(self):
        from app.uopti_backhaul_lifecycle import ManagedBackhaulPairHold
        self.saved["ci-ir"] = True
        with self.assertRaisesRegex(ManagedBackhaulPairHold,
                                    "BACKHAUL_PAIR_ALREADY_PRESENT"):
            await self.run_pair()
        self.client.send_to_node.assert_not_awaited()

    async def test_old_node_status_without_record_proof_fails_closed(self):
        from app.uopti_backhaul_lifecycle import ManagedBackhaulPairHold
        async def old_status(node_id, *, method, target, timeout):
            return {"status": "success", "data": {"active": False}}
        self.client._signed_agent_request.side_effect = old_status
        with self.assertRaisesRegex(ManagedBackhaulPairHold,
                                    "BACKHAUL_PAIR_SIGNED_STATUS_UNVERIFIED"):
            await self.run_pair()
        self.client.send_to_node.assert_not_awaited()

    async def test_existing_frp_identity_not_removed(self):
        from app.uopti_backhaul_lifecycle import ManagedBackhaulPairHold
        async def owner_status(node_id, *, method, target, timeout):
            if node_id == "ci-ir":
                return {"status": "success",
                        "data": {"active": True, "type": "frp",
                                 "record_present": True, "record_core": "frp"}}
            return await self.status(node_id, method=method,
                                     target=target, timeout=timeout)
        self.client._signed_agent_request.side_effect = owner_status
        with self.assertRaisesRegex(ManagedBackhaulPairHold,
                                    "BACKHAUL_PAIR_EXISTING_ID_UNTRUSTED"):
            await self.run_pair()
        self.db.execute.assert_not_awaited()
        self.client.send_to_node.assert_not_awaited()

    async def test_concurrent_pending_claim_refused_before_node_write(self):
        from types import SimpleNamespace
        from app.uopti_backhaul_lifecycle import ManagedBackhaulPairHold
        self.db.execute.return_value = SimpleNamespace(rowcount=0)
        with self.assertRaisesRegex(ManagedBackhaulPairHold,
                                    "BACKHAUL_PAIR_CONCURRENT_APPLY"):
            await self.run_pair()
        self.db.rollback.assert_awaited_once()
        self.client.send_to_node.assert_not_awaited()

    async def test_real_apply_route_uses_pair_not_legacy_path(self):
        from types import SimpleNamespace
        from app.routers import tunnels as routes

        class Result:
            def __init__(self, row):
                self.row = row

            def scalar_one_or_none(self):
                return self.row

        ir = SimpleNamespace(id="ci-ir", node_metadata={"role": "iran"})
        foreign = SimpleNamespace(id="ci-foreign",
                                  node_metadata={"role": "foreign"})
        self.db.execute.side_effect = [
            Result(self.tunnel), Result(ir), Result(foreign),
            SimpleNamespace(rowcount=1),
        ]
        with patch.object(routes, "require_managed_tunnel_pair",
                          new_callable=AsyncMock) as admit:
            with patch.object(routes, "NodeClient", return_value=self.client):
                out = await routes.apply_tunnel(
                    self.tunnel.id, SimpleNamespace(), self.db)
        admit.assert_awaited_once()
        self.assertEqual(out["status"], "applied")
        self.assertEqual(self.tunnel.status, "active")
        self.assertEqual(len(self.actions), 2)


class FrpStandardWssTest(unittest.TestCase):
    def test_default_off_does_not_force_tcp_frp_to_wss(self):
        with patch.dict(os.environ, {"PANEL_ADDRESS": "panel.example.org:443",
                                     "SMITE_FRP_STANDARD_WSS": "0"}):
            self.assertEqual(frp.frp_standard_wss_host(), "")
            self.assertEqual(frp.frp_client_server_port({}, 7000), 7000)
            self.assertEqual(frp.frp_tls_transport_yaml({}), "")

    def test_explicit_wss_443_uses_existing_domain(self):
        with patch.dict(os.environ, {"PANEL_ADDRESS": "panel.example.org:443",
                                     "SMITE_FRP_STANDARD_WSS": "1"}):
            self.assertEqual(frp.frp_standard_wss_host(), "panel.example.org")
            self.assertEqual(frp.frp_client_server_addr("127.0.0.1"), "panel.example.org")
            self.assertEqual(frp.frp_client_server_port({}, 7000), 443)
            self.assertIn("protocol: wss", frp.frp_tls_transport_yaml({}))
            with self.assertRaises(ValueError):
                frp.frp_client_server_port({"frp_gateway_port": 8443}, 7000)
            with self.assertRaises(ValueError):
                frp.frp_tls_transport_yaml({"frp_tls_server_name": "evil.example.org"})

    def test_updated_adapter_contains_opt_in_frp_and_pre_stop_backhaul_guard(self):
        text = (ROOT / "node/app/core_adapters.py").read_text()
        self.assertIn("server_port = frp_client_server_port", text)
        self.assertIn("frp_standard_wss_host()", text)
        self.assertIn("normalize_node_spec(spec)", text)
        self.assertLess(
            text.index("spec = normalize_node_spec(spec)"),
            text.index("if tunnel_id in self.processes:", text.index("class BackhaulAdapter:")),
        )
        self.assertIn('if spec.get("uopti_standard_backhaul") is True:', text)
        self.assertIn('os.fchmod(cfg.fileno(), 0o600)', text)
        self.assertIn('if spec.get("uopti_standard_backhaul") is not True:', text)


if __name__ == "__main__":
    unittest.main()
