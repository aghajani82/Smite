"""Read-only, fail-closed reconciliation of a legacy failed FRP second row.

A failed Smite database status does not imply the signed KH client was never
started. No deletion, process signaling, signed POST, credential exposure or
database writes are performed here. A candidate can only be approved for a
subsequent *separately authorized* cleanup after both signed Node inventories
and the existing owner's live listeners have been checked by the caller.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping, Collection


@dataclass(frozen=True)
class LegacyFrpRecoveryReview:
    safe_for_separate_cleanup_review: bool
    reason: str


def review_legacy_failed_frp_row(
    *,
    legacy_status: str,
    legacy_core: str,
    legacy_type: str,
    legacy_port: int,
    legacy_is_shared_child: bool,
    owner_status: str,
    owner_port: int,
    ir_signed_owner_proof: Mapping | None,
    kh_signed_client_inventory: Mapping | None,
    active_leases_for_port: Collection[str] | None,
    tunnel_id: str,
) -> LegacyFrpRecoveryReview:
    def hold(why: str) -> LegacyFrpRecoveryReview:
        return LegacyFrpRecoveryReview(False, why)

    if not tunnel_id or not isinstance(tunnel_id, str):
        return hold("LEGACY_ID_UNKNOWN")
    if legacy_core != "frp" or legacy_type != "tcp" or legacy_status != "error":
        return hold("NOT_FAILED_LEGACY_FRP_TCP")
    if legacy_is_shared_child:
        return hold("ALREADY_SHARED_CHILD")
    if type(legacy_port) is not int or not 1024 <= legacy_port <= 65535:
        return hold("INVALID_LEGACY_PORT")
    if owner_status != "active" or owner_port != 7000:
        return hold("OWNER_NOT_VERIFIED")
    if not isinstance(ir_signed_owner_proof, Mapping) or ir_signed_owner_proof.get("status") != "success":
        return hold("IR_SIGNED_PROOF_MISSING")
    owners = ir_signed_owner_proof.get("owners")
    if not isinstance(owners, list) or len(owners) != 1 or not isinstance(owners[0], Mapping):
        return hold("IR_OWNER_AMBIGUOUS")
    owner = owners[0]
    if owner.get("control_port") != 7000 or not isinstance(owner.get("proxy_ports"), list):
        return hold("IR_OWNER_UNTRUSTED")
    if legacy_port in owner["proxy_ports"]:
        return hold("IR_PROXY_PORT_STILL_ACTIVE")
    if not isinstance(kh_signed_client_inventory, Mapping) or kh_signed_client_inventory.get("status") != "success":
        return hold("KH_SIGNED_PROOF_MISSING")
    # Explicit, signed, *complete* client status inventory is mandatory.
    # A missing/unknown inventory must NEVER be interpreted as empty.
    items = kh_signed_client_inventory.get("tunnel_ids")
    if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
        return hold("KH_TUNNEL_INVENTORY_UNTRUSTED")
    if tunnel_id in items:
        return hold("KH_LEGACY_CLIENT_MAY_BE_ACTIVE")
    if active_leases_for_port is None:
        return hold("LEASE_INVENTORY_MISSING")
    if list(active_leases_for_port):
        return hold("REMOTE_PORT_ALREADY_LEASED")
    return LegacyFrpRecoveryReview(True, "ELIGIBLE_FOR_SEPARATE_OPERATOR_APPROVED_CLEANUP")
