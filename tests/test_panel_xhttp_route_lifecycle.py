"""Panel route orchestration tests; all Node and Broker calls are mocked."""
from __future__ import annotations

import unittest
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))
from app import xhttp_route_lifecycle as lifecycle


class Query:
    def __init__(self, model):
        self.model = model

    def where(self, *_args):
        return self


class Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class FakeDb:
    def __init__(self, *values):
        self.values = iter(values)

    async def execute(self, _query):
        return Result(next(self.values))


def objects():
    owner = SimpleNamespace(
        id="owner-frps-0001", core="frp", status="active",
        iran_node_id="node-ir-0001", node_id="node-ir-0001",
        foreign_node_id="node-kh-0001",
    )
    child = SimpleNamespace(
        id="child-frp-0001", core="frp", status="active",
        spec={"shared_frps_owner": owner.id}, iran_node_id="node-ir-0001",
        node_id="node-ir-0001", foreign_node_id="node-kh-0001",
    )
    lease = SimpleNamespace(
        tunnel_id=child.id, iran_node_id="node-ir-0001",
        foreign_node_id="node-kh-0001", owner_tunnel_id=owner.id,
        remote_port=45121,
    )
    ir = SimpleNamespace(id="node-ir-0001", node_metadata={"role": "iran"})
    kh = SimpleNamespace(id="node-kh-0001", node_metadata={"role": "foreign"})
    return child, lease, owner, ir, kh


class Client:
    def __init__(self):
        self.forwarded = None

    async def get_verified_frps_owners(self, node_id):
        assert node_id == "node-ir-0001"
        return {"status": "success", "owners": [{
            "tunnel_id": "owner-frps-0001", "control_port": 7000,
            "proxy_ports": [45121],
        }]}

    async def get_signed_sanaei_xhttp_inbounds(self, node_id):
        assert node_id == "node-kh-0001"
        return {"status": "success", "schema_version": 1, "inbounds": [{
            "port": 45121, "listen": "127.0.0.1", "protocol": "vless",
            "network": "xhttp", "path": "/45121/www", "enabled": True,
        }]}

    async def forward_uopti_xhttp_route(self, node_id, wire):
        self.forwarded = (node_id, wire)
        return {"status": "success", "result": "route_added"}


class RouteLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_route_uses_live_proofs_and_durable_lease_binding(self):
        child, lease, owner, ir, kh = objects()
        db = FakeDb(child, lease, owner, ir, kh)
        client = Client()
        captured = {}

        def sign(binding, *, dedicated_broker_key, now):
            captured.update(binding=binding, key=dedicated_broker_key, now=now)
            return b"signed-intent"

        with patch.object(lifecycle, "select", side_effect=lambda model: Query(model)), \
             patch.object(lifecycle, "_broker_key", return_value=b"k" * 32), \
             patch.object(lifecycle, "sign_route_intent", side_effect=sign):
            result = await lifecycle.register_xhttp_route(
                db=db, tunnel_id=child.id, inbound_port=45121,
                client=client, now=123456,
            )

        self.assertEqual(result["result"], "route_registered")
        self.assertEqual(client.forwarded, (ir.id, b"signed-intent"))
        binding = captured["binding"]
        self.assertEqual((binding.ir_node, binding.kh_node, binding.owner,
                          binding.child, binding.lease, binding.port, binding.path),
                         (ir.id, kh.id, owner.id, child.id, child.id,
                          45121, "/45121/www"))
        self.assertEqual(captured["key"], b"k" * 32)
        self.assertEqual(captured["now"], 123456)

    async def test_lease_port_mismatch_holds_before_sign_or_forward(self):
        child, lease, owner, ir, kh = objects()
        db = FakeDb(child, lease, owner, ir, kh)
        client = Client()
        with patch.object(lifecycle, "select", side_effect=lambda model: Query(model)), \
             patch.object(lifecycle, "_broker_key") as key_reader:
            with self.assertRaisesRegex(lifecycle.XhttpRouteHold,
                                        "ACTIVE_UNIQUE_LEASE_MISMATCH"):
                await lifecycle.register_xhttp_route(
                    db=db, tunnel_id=child.id, inbound_port=49328,
                    client=client, now=123456,
                )
        key_reader.assert_not_called()
        self.assertIsNone(client.forwarded)

    async def test_inbound_picker_returns_only_sanitized_signed_facts(self):
        child, lease, *_ = objects()
        db = FakeDb(child, lease)

        class InventoryClient:
            async def get_signed_sanaei_xhttp_inbounds(self, node_id):
                self.node_id = node_id
                return {"status": "success", "schema_version": 1,
                        "inbounds": [{"port": 45121, "listen": "127.0.0.1",
                                      "protocol": "vless", "network": "xhttp",
                                      "path": "/45121/www", "enabled": True}]}

        client = InventoryClient()
        with patch.object(lifecycle, "select", side_effect=lambda model: Query(model)):
            choices = await lifecycle.list_child_xhttp_inbounds(
                db=db, tunnel_id=child.id, client=client,
            )
        self.assertEqual(client.node_id, "node-kh-0001")
        self.assertEqual(choices, [{"port": 45121, "path": "/45121/www"}])


if __name__ == "__main__":
    unittest.main()
