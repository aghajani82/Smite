"""Strict, read-only FRPS owner runtime evidence for Signed RC2.

Never accepts DB status alone as proof that an FRPS is alive. Only a
tracked, server-mode FRPS process on 127.0.0.1:7000 with a matching
owner PID and listener qualifies. Never exposes FRP credentials.
"""
from __future__ import annotations

import psutil


def active_signed_frps_owners(
    adapter_manager,
    *,
    listeners=None,
) -> list[dict[str, object]]:
    # Fail closed on incomplete runtime or inaccessible process sockets.
    try:
        configs = adapter_manager.tunnel_configs
        adapters = adapter_manager.active_tunnels
        conns = psutil.net_connections(kind="tcp") if listeners is None else listeners
        live_pids = {
            getattr(conn, "pid", None)
            for conn in conns
            if (
                getattr(conn, "status", None) == psutil.CONN_LISTEN
                and getattr(getattr(conn, "laddr", None), "ip", None) == "127.0.0.1"
                and getattr(getattr(conn, "laddr", None), "port", None) == 7000
                and isinstance(getattr(conn, "pid", None), int)
            )
        }
        if not live_pids:
            return []
        owners = []
        for tunnel_id, config in configs.items():
            if not isinstance(config, dict) or config.get("core") != "frp":
                continue
            spec = config.get("spec")
            if not isinstance(spec, dict) or spec.get("mode") != "server":
                continue
            if spec.get("bind_port") != 7000:
                continue
            adapter = adapters.get(tunnel_id)
            if not adapter or getattr(adapter, "name", None) != "frp":
                continue
            proc = getattr(adapter, "processes", {}).get(tunnel_id)
            if not proc or proc.poll() is not None or proc.pid not in live_pids:
                continue
            owners.append({"tunnel_id": tunnel_id, "control_port": 7000})
        # More than one owner of the same listener is an invalid runtime,
        # never declare an ambiguous singleton valid.
        return owners if len(owners) == 1 else []
    except Exception:
        return []
