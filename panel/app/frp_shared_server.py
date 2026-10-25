"""Fail-closed planning for explicitly owned, shared FRPS remote proxy ports.

This module is deliberately side-effect-free and NOT wired into tunnel Apply.
It MUST NOT be used as a substitute for signed runtime owner verification.
The active FRPS owner keeps port 7000; a child receives only a client proxy
spec and MUST NOT start a second FRPS process.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Mapping, Collection


_ID = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
SIGNED_FRPS_CONTROL_PORT = 7000


class SharedFrpAdmissionDenied(ValueError):
    """Stable, non-secret reason for refusing unsafe multi-proxy admission."""


@dataclass(frozen=True)
class SharedFrpPlan:
    owner_tunnel_id: str
    remote_port: int
    server_control_port: int
    # Never dump a planned spec; it contains the owner's shared FRP token.
    client_spec: dict[str, Any] = field(repr=False)

    @property
    def requires_ir_server_apply(self) -> bool:
        return False


def _port(value: Any, label: str) -> int:
    if isinstance(value, bool) or not (
        isinstance(value, int) or
        (isinstance(value, str) and value.isascii() and value.isdecimal())
    ):
        raise SharedFrpAdmissionDenied(f"{label} is not a port")
    parsed = int(value)
    if not 1024 <= parsed <= 65535:
        raise SharedFrpAdmissionDenied(f"{label} is out of allowed range")
    return parsed


def _child_pair(spec: Mapping[str, Any]) -> tuple[int, int]:
    ports = spec.get("ports")
    if ports is not None:
        if not isinstance(ports, list) or len(ports) != 1:
            raise SharedFrpAdmissionDenied("Exactly one forwarded port is required")
        pair = ports[0]
        if isinstance(pair, dict) and set(pair) == {"local", "remote"}:
            return _port(pair["local"], "Local port"), _port(pair["remote"], "Remote port")
        if isinstance(pair, int) or isinstance(pair, str):
            port = _port(pair, "Forwarded port")
            return port, port
        raise SharedFrpAdmissionDenied("Unrecognized forwarded port entry")
    local = spec.get("local_port")
    remote = spec.get("remote_port", spec.get("listen_port"))
    if local is None or remote is None:
        raise SharedFrpAdmissionDenied("Missing explicit local and remote ports")
    return _port(local, "Local port"), _port(remote, "Remote port")


def plan_shared_frp_proxy(
    *,
    owner_tunnel_id: str,
    requested_owner_tunnel_id: str,
    owner_node_id: str,
    child_node_id: str,
    owner_status: str,
    owner_core: str,
    owner_type: str,
    owner_spec: Mapping[str, Any],
    child_spec: Mapping[str, Any],
    child_type: str,
    occupied_remote_ports: Collection[int],
    server_addr: str,
) -> SharedFrpPlan:
    """Plan an additional proxy, refusing to create or reconfigure FRPS.

    Caller MUST verify that the owner is the live, approved signed Node's
    existing FRPS process and serialize port allocation against peers before
    using this plan. A DB status of 'active' alone is insufficient.
    `occupied_remote_ports` MUST cover every existing remote proxy.
    """
    if not isinstance(owner_tunnel_id, str) or not _ID.fullmatch(owner_tunnel_id):
        raise SharedFrpAdmissionDenied("FRPS owner identity invalid")
    if requested_owner_tunnel_id != owner_tunnel_id:
        raise SharedFrpAdmissionDenied("Explicit FRPS owner selection required")
    if not owner_node_id or not child_node_id or owner_node_id != child_node_id:
        raise SharedFrpAdmissionDenied("FRPS owner and proxy belong to different Nodes")
    if owner_status != "active" or owner_core != "frp" or owner_type.lower() != "tcp":
        raise SharedFrpAdmissionDenied("FRPS owner is not an active TCP tunnel")
    if child_type.lower() != "tcp":
        raise SharedFrpAdmissionDenied("Shared FRPS supports TCP proxy only")
    if not isinstance(owner_spec, Mapping) or not isinstance(child_spec, Mapping):
        raise SharedFrpAdmissionDenied("Missing FRP specification")
    if _port(owner_spec.get("bind_port"), "Owner control port") != SIGNED_FRPS_CONTROL_PORT:
        raise SharedFrpAdmissionDenied("Shared owner must use approved control port")
    if _port(child_spec.get("bind_port"), "Child control port") != SIGNED_FRPS_CONTROL_PORT:
        raise SharedFrpAdmissionDenied("Child control port differs from approved FRPS")
    if child_spec.get("shared_frps_owner") != owner_tunnel_id:
        raise SharedFrpAdmissionDenied("Child shared owner marker missing")
    if child_spec.get("mode") not in (None, "client"):
        raise SharedFrpAdmissionDenied("Child must not start a server")
    if child_spec.get("local_ip", "127.0.0.1") != "127.0.0.1":
        raise SharedFrpAdmissionDenied("Foreign proxy local target must be loopback")
    local_port, remote_port = _child_pair(child_spec)
    if local_port != remote_port:
        raise SharedFrpAdmissionDenied("Dynamic XHTTP port pair must match")
    if occupied_remote_ports is None:
        raise SharedFrpAdmissionDenied("Remote port inventory required")
    try:
        occupied = {_port(v, "Existing remote port") for v in occupied_remote_ports}
    except TypeError as exc:
        raise SharedFrpAdmissionDenied("Invalid remote port inventory") from exc
    if remote_port in occupied:
        raise SharedFrpAdmissionDenied("Remote port already reserved")
    token = owner_spec.get("token")
    if not isinstance(token, str) or not token:
        raise SharedFrpAdmissionDenied("Existing FRPS owner token unavailable")
    # The child must never supply OR persist a copy of the FRPS secret.
    # Only the verified owner's stored token is used in the transient
    # signed client Apply, never in a user-supplied child Tunnel spec.
    if "token" in child_spec:
        raise SharedFrpAdmissionDenied("Child may not supply an FRPS token")
    if not isinstance(server_addr, str) or not server_addr.strip():
        raise SharedFrpAdmissionDenied("Approved IR FRPS address missing")

    # Do not pass an unreviewed server-mode child spec to the Node adapter.
    client_spec = {
        "mode": "client",
        "type": "tcp",
        "server_addr": server_addr,
        "server_port": SIGNED_FRPS_CONTROL_PORT,
        "token": token,
        "local_ip": "127.0.0.1",
        "ports": [{"local": local_port, "remote": remote_port}],
    }
    return SharedFrpPlan(
        owner_tunnel_id=owner_tunnel_id,
        remote_port=remote_port,
        server_control_port=SIGNED_FRPS_CONTROL_PORT,
        client_spec=client_spec,
    )
