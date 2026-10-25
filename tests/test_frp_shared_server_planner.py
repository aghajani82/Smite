"""Offline contract tests: shared FRPS planning never starts a second server."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

from app.frp_shared_server import (
    SharedFrpAdmissionDenied,
    plan_shared_frp_proxy,
)

OWNER = "trial_frp_45121"
SECRET = "unit-test-only-frp-token-not-for-production"


def valid(**overrides):
    inputs = {
        "owner_tunnel_id": OWNER,
        "requested_owner_tunnel_id": OWNER,
        "owner_node_id": "node-ir-identity",
        "child_node_id": "node-ir-identity",
        "owner_status": "active",
        "owner_core": "frp",
        "owner_type": "tcp",
        "owner_spec": {"bind_port": 7000, "token": SECRET},
        "child_spec": {
            "shared_frps_owner": OWNER,
            "bind_port": 7000,
            "local_ip": "127.0.0.1",
            "ports": [{"local": 49328, "remote": 49328}],
        },
        "child_type": "tcp",
        "occupied_remote_ports": [45121],
        "server_addr": "ir.example.test",
    }
    inputs.update(overrides)
    return inputs


class SharedFrpsPlanningTests(unittest.TestCase):
    def test_new_proxy_uses_existing_owner_and_never_creates_second_frps(self):
        plan = plan_shared_frp_proxy(**valid())
        self.assertFalse(plan.requires_ir_server_apply)
        self.assertEqual(plan.owner_tunnel_id, OWNER)
        self.assertEqual(plan.remote_port, 49328)
        self.assertEqual(plan.server_control_port, 7000)
        self.assertEqual(plan.client_spec["mode"], "client")
        self.assertEqual(plan.client_spec["local_ip"], "127.0.0.1")
        self.assertEqual(plan.client_spec["token"], SECRET)
        self.assertEqual(plan.client_spec["ports"], [{"local": 49328, "remote": 49328}])
        self.assertNotIn("bind_port", plan.client_spec)
        self.assertNotIn(SECRET, repr(plan))
        self.assertNotIn("token", repr(plan))

    def deny(self, **changes):
        with self.assertRaises(SharedFrpAdmissionDenied):
            plan_shared_frp_proxy(**valid(**changes))

    def test_explicit_owner_is_mandatory(self):
        self.deny(requested_owner_tunnel_id="")
        self.deny(child_spec={
            "bind_port": 7000,
            "ports": [{"local": 49328, "remote": 49328}],
        })

    def test_owner_must_be_active_tcp_frp_on_same_signed_node(self):
        self.deny(owner_status="error")
        self.deny(owner_core="backhaul")
        self.deny(owner_type="udp")
        self.deny(child_type="udp")
        self.deny(child_node_id="different-node")
        self.deny(owner_tunnel_id="../unsafe")

    def test_never_install_second_server_or_external_target(self):
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "mode": "server",
            "bind_port": 7000, "ports": [49328]})
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "local_ip": "0.0.0.0", "ports": [49328]})

    def test_duplicate_ports_or_wrong_control_port_denied(self):
        self.deny(occupied_remote_ports=[45121, 49328])
        self.deny(occupied_remote_ports=None)
        self.deny(owner_spec={"bind_port": 7001, "token": SECRET})
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7001,
            "ports": [49328]})

    def test_child_token_must_not_silently_replace_existing_owner(self):
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "ports": [49328], "token": "different-token"})
        # Even the correct secret must never be persisted in child specs.
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "ports": [49328], "token": SECRET})
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "ports": [49328], "token": ""})
        self.deny(owner_spec={"bind_port": 7000, "token": ""})

    def test_multiple_ports_and_mismatched_pairs_denied(self):
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "ports": [45121, 49328]})
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "ports": [{"local": 49328, "remote": 49329}]})
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "ports": [{"local": 49328, "remote": 49328, "unexpected": 1}]})

    def test_port_boundaries_and_no_implicit_discovery(self):
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "ports": [0]})
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "ports": [True]})
        self.deny(child_spec={
            "shared_frps_owner": OWNER, "bind_port": 7000,
            "ports": [80]})
        self.deny(server_addr="")

    def test_explicit_port_fields_supported(self):
        spec = {
            "shared_frps_owner": OWNER, "bind_port": "7000",
            "local_port": "49328", "remote_port": "49328",
        }
        plan = plan_shared_frp_proxy(**valid(child_spec=spec))
        self.assertEqual(plan.remote_port, 49328)


if __name__ == "__main__":
    unittest.main()
