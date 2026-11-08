"""Fail-closed Backhaul update admission before any DB commit or restart.

Standard Backhaul must not silently lose its opt-in flag or replace its
loopback-only port mappings during an edit. The validator does not start,
stop, or mutate any service.
"""
from __future__ import annotations

from app.uopti_backhaul_standard import (
    StandardBackhaulSpecError, compile_standard_specs,
)


def require_managed_backhaul_activation(
    *, core: str, spec: dict | None, management_mode: str,
) -> None:
    """Managed creation/reapply must not activate unapproved legacy listeners.

    This check is purely local and precedes DB writes and Node commands.
    It does not grant real-host Backhaul activation or prove TLS/443.
    """
    if core != "backhaul" or management_mode != "managed":
        return
    if not isinstance(spec, dict) or spec.get("uopti_standard_backhaul") is not True:
        raise StandardBackhaulSpecError(
            "Managed Backhaul requires an explicitly approved Standard spec"
        )
    compile_standard_specs(
        spec,
        data_port=spec.get("data_port", 56053),
        control_port=spec.get("control_port", 3080),
        bridge_port=spec.get("bridge_port", 13080),
    )


def review_backhaul_edit(
    *, core: str, old_spec: dict | None, proposed_spec: dict | None,
) -> bool:
    """Return True only for an already opted-in, fully checked Standard spec."""
    if core != "backhaul" or proposed_spec is None:
        return False
    old = isinstance(old_spec, dict) and old_spec.get("uopti_standard_backhaul") is True
    new = isinstance(proposed_spec, dict) and proposed_spec.get("uopti_standard_backhaul") is True
    if old and not new:
        raise StandardBackhaulSpecError("Standard Backhaul opt-in cannot be removed by edit")
    if new:
        compile_standard_specs(
            proposed_spec,
            data_port=proposed_spec.get("data_port", 56053),
            control_port=proposed_spec.get("control_port", 3080),
            bridge_port=proposed_spec.get("bridge_port", 13080),
        )
    return bool(new)


class ManagedBackhaulPairHold(RuntimeError):
    """Fixed-code denial; never propagate tokens or signed Node error bodies."""


async def apply_managed_backhaul_pair(*, tunnel, iran_node_id: str,
                                      foreign_node_id: str, client, db) -> dict:
    """Exact new, pending Backhaul pair Apply using existing signed Node API.

    The Node engine remains independent of FRP. A remote timeout is ambiguous:
    inspect each exact per-tunnel signed status before any compensating Remove.
    An unverified rollback remains quarantined; never claim success or retry.
    This is a Panel process transaction, not proof of production TLS/data flow.
    """
    from urllib.parse import quote
    from sqlalchemy import update
    from app.config import settings
    from app.models import Tunnel

    if (settings.smite_engine_management_mode != "managed"
            or settings.smite_panel_agent_auth_mode != "signed"
            or tunnel.core != "backhaul" or tunnel.status != "pending"
            or not iran_node_id or not foreign_node_id
            or iran_node_id == foreign_node_id
            or not isinstance(tunnel.id, str) or not tunnel.id
            or len(tunnel.id) > 128):
        raise ManagedBackhaulPairHold("BACKHAUL_PAIR_PENDING_SIGNED_REQUIRED")

    target = ("/api/agent/tunnels/status?tunnel_id="
              + quote(tunnel.id, safe=""))

    async def observed(node_id: str) -> bool:
        reply = await client._signed_agent_request(
            node_id, method="GET", target=target, timeout=3.0)
        if (not isinstance(reply, dict) or reply.get("status") != "success"
                or not isinstance(reply.get("data"), dict)):
            raise ManagedBackhaulPairHold("BACKHAUL_PAIR_SIGNED_STATUS_UNVERIFIED")
        data = reply["data"]
        if (type(data.get("active")) is not bool
                or type(data.get("record_present")) is not bool):
            # An older Node lacking the persisted-record evidence fails closed.
            raise ManagedBackhaulPairHold("BACKHAUL_PAIR_SIGNED_STATUS_UNVERIFIED")
        if data["record_present"]:
            if data.get("record_core") not in (
                    "backhaul", "frp", "gost", "rathole", "chisel"):
                raise ManagedBackhaulPairHold("BACKHAUL_PAIR_EXISTING_ID_UNTRUSTED")
        elif data.get("record_core") is not None:
            raise ManagedBackhaulPairHold("BACKHAUL_PAIR_SIGNED_STATUS_UNVERIFIED")
        if data["active"] and (
                data.get("type") != "backhaul"
                or data.get("record_core") != "backhaul"):
            raise ManagedBackhaulPairHold("BACKHAUL_PAIR_EXISTING_ID_UNTRUSTED")
        return data

    # Verify BOTH full records before any write: an inactive persisted ID
    # (including dormant FRP) must never look like an unused Backhaul ID.
    preflight = (await observed(iran_node_id), await observed(foreign_node_id))
    if any(state["active"] or state["record_present"] for state in preflight):
        raise ManagedBackhaulPairHold("BACKHAUL_PAIR_ALREADY_PRESENT")

    # CAS prevents two Panel requests from both claiming the same pending
    # database row. A crash leaves "applying", not a falsely active tunnel.
    claim = await db.execute(
        update(Tunnel).where(
            Tunnel.id == tunnel.id, Tunnel.status == "pending"
        ).values(status="applying"))
    if claim.rowcount != 1:
        await db.rollback()
        raise ManagedBackhaulPairHold("BACKHAUL_PAIR_CONCURRENT_APPLY")
    tunnel.status = "applying"
    await db.commit()

    attempted: list[str] = []
    acknowledged: set[str] = set()
    try:
        for node_id, mode in ((iran_node_id, "server"),
                              (foreign_node_id, "client")):
            attempted.append(node_id)
            reply = await client.send_to_node(
                node_id=node_id, endpoint="/api/agent/tunnels/apply",
                data={"tunnel_id": tunnel.id, "core": "backhaul",
                      "type": tunnel.type, "spec": {**tunnel.spec, "mode": mode}})
            if not isinstance(reply, dict) or reply.get("status") != "success":
                raise ManagedBackhaulPairHold("BACKHAUL_PAIR_NODE_APPLY_FAILED")
            acknowledged.add(node_id)
            state = await observed(node_id)
            if (not state["active"] or not state["record_present"]
                    or state["record_core"] != "backhaul"):
                raise ManagedBackhaulPairHold("BACKHAUL_PAIR_APPLY_NOT_RUNNING")
        final_states = (await observed(iran_node_id), await observed(foreign_node_id))
        if any(not state["active"] or not state["record_present"]
               or state["record_core"] != "backhaul" for state in final_states):
            raise ManagedBackhaulPairHold("BACKHAUL_PAIR_POSTCHECK_FAILED")
    except Exception:
        # Signed status first: an error/timeout may occur *after* Node Apply.
        # Remove only a newly observed active Backhaul for an attempted Node;
        # never remove FRP or a dormant pre-existing registry entry.
        clean = True
        for node_id in (foreign_node_id, iran_node_id):
            try:
                state = await observed(node_id)
                if state["record_present"] and state["record_core"] != "backhaul":
                    # Never compensate an FRP (including dormant saved FRP).
                    clean = False
                    continue
                if node_id in attempted and (state["active"] or state["record_present"]):
                    # Baseline was empty; compensate this newly observed ID,
                    # even if the Backhaul process exited after saving it.
                    reply = await client.send_to_node(
                        node_id=node_id, endpoint="/api/agent/tunnels/remove",
                        data={"tunnel_id": tunnel.id})
                    if not isinstance(reply, dict) or reply.get("status") != "success":
                        clean = False
                    else:
                        after = await observed(node_id)
                        if after["active"] or after["record_present"]:
                            clean = False
                elif state["active"] or state["record_present"]:
                    clean = False
                elif node_id in attempted and node_id in acknowledged:
                    # Acknowledged then removed externally: require manual
                    # confirmation rather than silently accepting a race.
                    clean = False
            except Exception:
                clean = False
        tunnel.status = "pending" if clean else "error"
        tunnel.error_message = (
            "BACKHAUL_PAIR_ROLLED_BACK_REVIEW_BEFORE_RETRY" if clean
            else "BACKHAUL_PAIR_RECOVERY_REQUIRED")
        await db.commit()
        raise ManagedBackhaulPairHold(
            "BACKHAUL_PAIR_ROLLED_BACK" if clean
            else "BACKHAUL_PAIR_RECOVERY_REQUIRED") from None

    tunnel.status = "active"
    tunnel.error_message = None
    await db.commit()
    return {"status": "applied", "message": "Signed Backhaul pair applied"}
