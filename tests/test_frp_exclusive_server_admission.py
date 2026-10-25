"""Offline Panel exclusive-FRPS contract: protect working owner on :7000."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "panel/app/frp_server_admission.py"
spec = importlib.util.spec_from_file_location("frp_server_admission_test", PATH)
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def row(id, port=7000, *, node="ir-id", state="active", core="frp"):
    return SimpleNamespace(
        id=id, core=core, status=state,
        iran_node_id=node, node_id=node,
        spec={"bind_port": port},
    )


class ExclusiveFrpsAdmissionTests(unittest.TestCase):
    def check(self, *, candidate=None, existing=None, node="ir-id", current_id=None):
        return admission.require_exclusive_frps_server_admission(
            candidate_spec={"bind_port": 7000} if candidate is None else candidate,
            owner_node_id=node,
            existing_tunnels=[] if existing is None else existing,
            current_tunnel_id=current_id,
        )

    def test_first_owner_allowed(self):
        self.assertIsNone(self.check())

    def test_duplicate_active_port_blocked_before_signed_apply(self):
        with self.assertRaisesRegex(
            admission.FrpsServerAdmissionDenied, "already owned"
        ):
            self.check(existing=[row("existing-45121")])

    def test_duplicate_pending_owner_is_also_reserved(self):
        with self.assertRaises(admission.FrpsServerAdmissionDenied):
            self.check(existing=[row("pending", state="pending")])

    def test_exact_same_owner_reapply_is_not_falsely_blocked(self):
        self.assertIsNone(
            self.check(existing=[row("owner")], current_id="owner")
        )

    def test_ir_node_identity_boundary(self):
        self.assertIsNone(
            self.check(existing=[row("foreign-owner", node="another-node")])
        )

    def test_different_control_port_does_not_conflict(self):
        self.assertIsNone(
            self.check(candidate={"bind_port": 7100}, existing=[row("first", 7000)])
        )

    def test_failed_db_row_not_treated_as_live_owner(self):
        self.assertIsNone(
            self.check(existing=[row("failed", state="error")])
        )

    def test_shared_flag_not_allowed_to_bypass_reviewed_client_path(self):
        with self.assertRaisesRegex(
            admission.FrpsServerAdmissionDenied, "not enabled"
        ):
            self.check(
                candidate={"bind_port": 7000, "shared_frps_owner": "first"}
            )

    def test_missing_or_untrusted_owner_state_denied(self):
        for invalid in (None, {}, []):
            with self.subTest(spec=invalid):
                with self.assertRaises(admission.FrpsServerAdmissionDenied):
                    self.check(existing=[
                        SimpleNamespace(
                            id="first", core="frp", status="active",
                            iran_node_id="ir-id", node_id="ir-id",
                            spec=invalid,
                        )
                    ])

    def test_invalid_port_or_missing_ir_node_denied(self):
        for port in (True, 0, 65536, "bad"):
            with self.subTest(port=port):
                with self.assertRaises(admission.FrpsServerAdmissionDenied):
                    self.check(candidate={"bind_port": port})
        with self.assertRaises(admission.FrpsServerAdmissionDenied):
            self.check(node="")

    def test_legacy_backhaul_is_outside_frp_owner_check(self):
        self.assertIsNone(
            self.check(existing=[row("backhaul", core="backhaul")])
        )


if __name__ == "__main__":
    unittest.main()
