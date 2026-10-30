"""Strict signed read-only attestation from actual local Node runtime.

This is not a route publisher and cannot mutate FRP, Sanaei or pairing.
Explicitly opt-in with an independent root-only Ed25519 key AFTER reviewed
deployment. Inert by default. Caller-selected port is only a filter;
all signed facts come directly from live FRPS or mounted Sanaei inventory.
"""
from __future__ import annotations
import os
import secrets
from pathlib import Path


class RuntimeAttestationHold(RuntimeError):
    pass


def collect(*, kind: str, port: int, settings, adapter_manager=None, now=None) -> dict:
    if (kind not in ("frps_owner", "xhttp_inbound")
            or type(port) is not int or not 1024 <= port <= 65535 or port==7000):
        raise RuntimeAttestationHold("INVALID_ATTESTATION_FILTER")
    key_path=os.environ.get("SMITE_STAGE15_APPROVAL_ATTESTATION_KEY","")
    if (not key_path.startswith("/") or ".." in Path(key_path).parts
            or settings.smite_agent_auth_mode!="strict"):
        raise RuntimeAttestationHold("ATTESTATION_NOT_ENROLLED")
    from app.agent_auth import read_identity
    from app.approval_attestation import attest
    node_id,_=read_identity(settings.smite_agent_identity_path)
    if kind=="frps_owner":
        if settings.node_role!="iran" or adapter_manager is None:
            raise RuntimeAttestationHold("WRONG_ATTESTATION_ROLE")
        from app.frp_owner_status import active_signed_frps_owners
        found=active_signed_frps_owners(adapter_manager)
        if (len(found)!=1 or port not in found[0].get("proxy_ports",())
                or type(found[0].get("tunnel_id")) is not str):
            raise RuntimeAttestationHold("LIVE_FRPS_OWNER_MISSING")
        facts={"tunnel_id":found[0]["tunnel_id"],"control_port":7000,"proxy_port":port}
    else:
        if settings.node_role!="foreign" or not settings.smite_sanaei_inventory_enabled:
            raise RuntimeAttestationHold("KH_INVENTORY_NOT_ENROLLED")
        from app.sanaei_inbound_inventory import list_approved_xhttp_inbounds
        entries=list_approved_xhttp_inbounds(settings.smite_sanaei_db_path)
        filtered=[i for i in entries if i["port"]==port]
        if len(filtered)!=1:
            raise RuntimeAttestationHold("UNIQUE_KH_INBOUND_MISSING")
        facts=filtered[0]
    return attest(kind=kind,node_id=node_id,facts=facts,
                  nonce=secrets.token_hex(16),key_path=Path(key_path),now=now)
