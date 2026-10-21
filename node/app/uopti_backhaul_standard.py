#!/usr/bin/env python3
"""Fail-closed, purely local Standard Backhaul specs for Smite v0.1.7.

Designed for opt-in persistent overlays only. This module never launches a
tunnel, changes any files, or makes network requests.
"""
from __future__ import annotations

FLAG = "uopti_standard_backhaul"
LOCALHOST = "127.0.0.1"
RESERVED = frozenset({443, 7000, 8000, 8443, 8888, 18476})


class StandardBackhaulSpecError(ValueError):
    """Reject an unsafe or ambiguous Standard Backhaul configuration."""


def port_number(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise StandardBackhaulSpecError(f"{label}: integer port required")
    raw = str(value)
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 5:
        raise StandardBackhaulSpecError(f"{label}: numeric port required")
    port = int(raw)
    if port < 1024 or port > 65535 or port in RESERVED:
        raise StandardBackhaulSpecError(f"{label}: forbidden or out of range")
    return port


def _same_port(value: object, expected: int, label: str) -> None:
    if value is not None and port_number(value, label) != expected:
        raise StandardBackhaulSpecError(f"{label}: conflicts with configured port")


def compile_standard_specs(
    incoming: dict,
    *,
    data_port: int = 56053,
    control_port: int = 3080,
    bridge_port: int = 13080,
) -> tuple[dict, dict]:
    """Normalize IR server and KH client. Never trust upstream wildcard binds.

    Backhaul 0.7.2 WS control/data share /channel and /tunnel/ID.
    WS is used only on loopback: KH Nginx verifies TLS to IR:443.
    """
    if not isinstance(incoming, dict) or incoming.get(FLAG) is not True:
        raise StandardBackhaulSpecError("Explicit Standard Backhaul opt-in required")

    p = port_number(data_port, "data_port")
    c = port_number(control_port, "control_port")
    b = port_number(bridge_port, "bridge_port")
    if len({p, c, b}) != 3:
        raise StandardBackhaulSpecError("Data, control and bridge ports must differ")

    if incoming.get("transport", incoming.get("type", "ws")) != "ws":
        raise StandardBackhaulSpecError("Standard Backhaul requires WS")
    if incoming.get("type") not in (None, "ws"):
        raise StandardBackhaulSpecError("Conflicting transport/type")
    if incoming.get("mode") not in (None, "server", "client"):
        raise StandardBackhaulSpecError("Invalid Backhaul role")
    if any(incoming.get(k) for k in (
        "tls_cert", "tls_key", "tls", "websocket_tls", "pprof",
        "web_port", "accept_udp", "sniffer",
    )):
        raise StandardBackhaulSpecError("Unexpected TLS, public listener or debug option")
    for name in ("server_options", "client_options"):
        if incoming.get(name) not in (None, {}):
            raise StandardBackhaulSpecError(f"Unsupported {name} in Standard mode")

    token = incoming.get("token")
    if not isinstance(token, str) or len(token) < 24 or not token.strip():
        raise StandardBackhaulSpecError("A generated Backhaul token >=24 characters is required")
    if any(ch in token for ch in "\r\n\x00"):
        raise StandardBackhaulSpecError("Unsafe token characters")

    _same_port(incoming.get("data_port"), p, "data_port")
    _same_port(incoming.get("control_port"), c, "control_port")
    _same_port(incoming.get("bridge_port"), b, "bridge_port")
    for name in ("public_port", "listen_port", "target_port", "remote_port"):
        _same_port(incoming.get(name), p, name)

    for name in ("target_host", "local_ip", "bind_ip"):
        if incoming.get(name) not in (None, "", LOCALHOST):
            raise StandardBackhaulSpecError(f"{name}: must be loopback")

    if incoming.get("bind_addr") not in (None, "", f"{LOCALHOST}:{c}"):
        raise StandardBackhaulSpecError("bind_addr must be IR loopback")
    if incoming.get("remote_addr") not in (None, "", f"{LOCALHOST}:{b}"):
        raise StandardBackhaulSpecError("remote_addr must use the KH local TLS bridge")

    mappings = incoming.get("ports", [p])
    if not isinstance(mappings, list) or len(mappings) != 1:
        raise StandardBackhaulSpecError("Exactly one data port mapping is required")
    mapping = str(mappings[0])
    if mapping not in {
        str(p),
        f"{p}={LOCALHOST}:{p}",
        f"{LOCALHOST}:{p}={LOCALHOST}:{p}",
    }:
        raise StandardBackhaulSpecError("Only loopback equal-port mappings are permitted")

    # Whitelisting avoids inheriting panel-supplied wildcard or debug options.
    common = {
        FLAG: True,
        "transport": "ws",
        "type": "ws",
        "token": token,
        "data_port": p,
        "control_port": c,
        "bridge_port": b,
        "target_host": LOCALHOST,
        "ports": [f"{LOCALHOST}:{p}={LOCALHOST}:{p}"],
    }
    server = {
        **common,
        "mode": "server",
        "bind_addr": f"{LOCALHOST}:{c}",
        "bind_ip": LOCALHOST,
        "public_port": p,
        "listen_port": p,
    }
    client = {
        **common,
        "mode": "client",
        "remote_addr": f"{LOCALHOST}:{b}",
    }
    return server, client


def normalize_node_spec(spec: dict) -> dict:
    """Validate *before* the Smite BackhaulAdapter stops an existing process."""
    if not isinstance(spec, dict) or spec.get(FLAG) is not True:
        raise StandardBackhaulSpecError("Standard node spec requires explicit opt-in")
    mode = spec.get("mode")
    if mode not in ("server", "client"):
        raise StandardBackhaulSpecError("Explicit server/client node role required")
    server, client = compile_standard_specs(
        spec,
        data_port=spec.get("data_port", 56053),
        control_port=spec.get("control_port", 3080),
        bridge_port=spec.get("bridge_port", 13080),
    )
    return server if mode == "server" else client
