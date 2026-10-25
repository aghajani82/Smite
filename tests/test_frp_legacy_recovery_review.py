"""Safe legacy failed-row preflight needs independent signed evidence."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
source=ROOT/"panel/app/frp_legacy_recovery_review.py"
s=importlib.util.spec_from_file_location("frp_legacy_recovery_review",source)
mod=importlib.util.module_from_spec(s)
import sys
sys.modules[s.name]=mod
s.loader.exec_module(mod)


def base(**updates):
    args=dict(
        legacy_status="error", legacy_core="frp", legacy_type="tcp",
        legacy_port=49328, legacy_is_shared_child=False,
        owner_status="active", owner_port=7000,
        ir_signed_owner_proof={"status":"success","owners":[
            {"tunnel_id":"owner-45121","control_port":7000,"proxy_ports":[45121]}
        ]},
        kh_signed_client_inventory={"status":"success","tunnel_ids":["owner-45121"]},
        active_leases_for_port=[], tunnel_id="legacy-49328",
    )
    args.update(updates)
    return args


class RecoveryReviewTests(unittest.TestCase):
    def test_explicit_both_signed_inventories_allows_review_not_deletion(self):
        decision=mod.review_legacy_failed_frp_row(**base())
        self.assertTrue(decision.safe_for_separate_cleanup_review)
        self.assertEqual(decision.reason,"ELIGIBLE_FOR_SEPARATE_OPERATOR_APPROVED_CLEANUP")
        self.assertFalse(hasattr(mod,"delete_legacy_row"))

    def deny(self,**kw):
        out=mod.review_legacy_failed_frp_row(**base(**kw))
        self.assertFalse(out.safe_for_separate_cleanup_review)
        self.assertNotIn("DO_NOT_LEAK",repr(out))

    def test_old_port_still_listening_means_hold(self):
        self.deny(ir_signed_owner_proof={"status":"success","owners":[
            {"tunnel_id":"owner","control_port":7000,"proxy_ports":[45121,49328]}]})

    def test_any_unknown_signed_proof_is_hold(self):
        self.deny(ir_signed_owner_proof=None)
        self.deny(kh_signed_client_inventory=None)
        self.deny(kh_signed_client_inventory={"status":"success"})
        self.deny(kh_signed_client_inventory={"status":"error","tunnel_ids":[]})
        self.deny(ir_signed_owner_proof={"status":"success","owners":[]})

    def test_child_client_still_present_is_hold(self):
        self.deny(kh_signed_client_inventory={
            "status":"success","tunnel_ids":["legacy-49328"]})

    def test_port_lease_may_not_be_reused(self):
        self.deny(active_leases_for_port=None)
        self.deny(active_leases_for_port=["active-child"])

    def test_only_specific_failed_legacy_frp_row_is_candidate(self):
        self.deny(legacy_status="active")
        self.deny(legacy_core="backhaul")
        self.deny(legacy_type="udp")
        self.deny(legacy_is_shared_child=True)
        self.deny(legacy_port=45121,ir_signed_owner_proof={
            "status":"success","owners":[
                {"control_port":7000,"proxy_ports":[45121]}]})
        self.deny(owner_status="error")
        self.deny(owner_port=7001)


if __name__=="__main__":
    unittest.main()
