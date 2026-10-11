"""Validated optional FRP TLS/SNI gateway settings for the Smite node.

Legacy tunnels omit both optional fields and keep their existing behavior.
"""

import re


_FRP_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def frp_client_server_port(spec, default_port):
    """Use a separate client-facing port without changing the FRPS bind port."""
    value = spec.get("frp_gateway_port")
    if value is None or value == "":
        return default_port
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("FRP gateway port must be a number between 1 and 65535")
    raw = str(value)
    if not raw.isascii() or not raw.isdecimal():
        raise ValueError("FRP gateway port must be a number between 1 and 65535")
    port = int(raw)
    if not 1 <= port <= 65535:
        raise ValueError("FRP gateway port must be between 1 and 65535")
    if not spec.get("frp_tls_server_name"):
        raise ValueError("FRP gateway port requires frp_tls_server_name")
    return port


def frp_tls_transport_yaml(spec):
    """Render an opt-in, TLS-first ClientHello with a safe, validated SNI."""
    value = spec.get("frp_tls_server_name")
    if value is None or value == "":
        if spec.get("frp_gateway_port") is not None and spec.get("frp_gateway_port") != "":
            raise ValueError("FRP gateway port requires frp_tls_server_name")
        return ""

    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("FRP TLS server name must be a valid DNS hostname")
    labels = value.split(".")
    if len(labels) < 2 or not all(_FRP_DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("FRP TLS server name must be a valid DNS hostname")

    return (
        "transport:\n"
        "  tls:\n"
        "    enable: true\n"
        f'    serverName: "{value}"\n'
        "    disableCustomTLSFirstByte: true\n"
    )
