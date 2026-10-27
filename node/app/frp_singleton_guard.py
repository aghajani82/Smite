"""Fail-closed FRPS server slot admission for the signed WSS gateway.

Read-only TCP listener inspection precedes any configuration write, existing
process removal or new frps start. This is a guard against running a second
independent FRPS on the same loopback control port, NOT a shared-FRPS
implementation. Runtime child proxies require a separate reviewed owner path.
"""
from __future__ import annotations

from typing import Any, Iterable

import psutil


class FrpsServerSlotDenied(RuntimeError):
    """A generic, secret-free denial: do not start a second server."""


def assert_frps_control_port_available(
    *, tunnel_id: str, control_port: Any,
    shared_frps_owner: Any = None,
    sockets: Iterable[Any] | None = None,
) -> None:
    if not isinstance(tunnel_id, str) or not tunnel_id:
        raise FrpsServerSlotDenied("FRPS tunnel identity missing")
    if shared_frps_owner is not None:
        raise FrpsServerSlotDenied("Shared FRPS child cannot start a new FRPS server")
    if isinstance(control_port, bool):
        raise FrpsServerSlotDenied("FRPS control port invalid")
    try:
        port = int(control_port)
    except (TypeError, ValueError, OverflowError) as exc:
        raise FrpsServerSlotDenied("FRPS control port invalid") from exc
    if port != 7000:
        raise FrpsServerSlotDenied("Signed WSS FRPS control port must be 7000")
    try:
        connections = psutil.net_connections(kind="tcp") if sockets is None else sockets
        for item in connections:
            address = getattr(item, "laddr", None)
            if not address or getattr(item, "status", None) != psutil.CONN_LISTEN:
                continue
            if getattr(address, "port", None) == port:
                # Includes a wildcard / IPv6 listener: fail closed.
                raise FrpsServerSlotDenied(
                    "FRPS control port already listening; shared owner required"
                )
    except FrpsServerSlotDenied:
        raise
    except Exception as exc:
        raise FrpsServerSlotDenied(
            "Cannot verify exclusive FRPS control port"
        ) from exc
