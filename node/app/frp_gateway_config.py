"""Opt-in Standard Smite FRP through the existing Panel hostname and WSS/443.

This helper is mounted only when the Standard FRP trial was selected.
Non-443/private transports keep their original FRP TCP behavior.
"""
import os
import re

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def frp_standard_wss_host():
    # Default OFF. No implicit FRP TCP -> WSS transport migration.
    if os.environ.get("SMITE_FRP_STANDARD_WSS", "") != "1":
        return ""
    address = os.environ.get("PANEL_ADDRESS", "").strip()
    if not address or "://" in address:
        return ""
    hostname, separator, port = address.rpartition(":")
    if not separator or port != "443":
        return ""
    if len(hostname) > 253 or not all(
        _HOST_LABEL.fullmatch(label) for label in hostname.split(".")
    ) or "." not in hostname:
        raise ValueError("Standard FRP WSS requires a valid Panel DNS hostname")
    return hostname


def require_shared_frps_wss(spec):
    """Refuse a shared child if KH cannot use the configured WSS/443 edge.

    This is a preflight for the EXISTING signed FRP child path; legacy
    independent clients are unaffected. Call it before replacing processes
    and again during cold-boot restore. No network or filesystem side effect.
    """
    if "shared_frps_owner" not in spec:
        return
    owner = spec.get("shared_frps_owner")
    if not isinstance(owner, str) or not owner or spec.get("mode") != "client":
        raise ValueError("Shared FRPS client owner or mode invalid")
    host = frp_standard_wss_host()
    if not host:
        raise ValueError("Shared FRPS client requires configured WSS/443")
    if spec.get("server_port") not in (7000, "7000"):
        raise ValueError("Shared FRPS client control port invalid")
    if spec.get("frp_gateway_port") not in (None, "", 443, "443"):
        raise ValueError("Shared FRPS client must use WSS/443")
    if spec.get("frp_tls_server_name") not in (None, "", host):
        raise ValueError("Shared FRPS client SNI differs from configured WSS host")


def frp_client_server_addr(original):
    return frp_standard_wss_host() or original


def frp_client_server_port(spec, default_port):
    host = frp_standard_wss_host()
    value = spec.get("frp_gateway_port")
    if host:
        if value not in (None, "", 443, "443"):
            raise ValueError("Standard FRP WSS uses the existing Panel port 443")
        return 443
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
    host = frp_standard_wss_host()
    if host:
        extra = spec.get("frp_tls_server_name")
        if extra not in (None, "", host):
            raise ValueError("WSS uses the existing Panel hostname, not a custom SNI")
        # FRP defaults to InsecureSkipVerify without trustedCaFile, even for
        # WSS. Use the image's OS CA bundle and the configured Panel DNS.
        return ("transport:\n  protocol: wss\n  tls:\n"
                "    enable: true\n"
                '    trustedCaFile: "/etc/ssl/certs/ca-certificates.crt"\n'
                f'    serverName: "{host}"\n')
    value = spec.get("frp_tls_server_name")
    if value is None or value == "":
        if spec.get("frp_gateway_port") not in (None, ""):
            raise ValueError("FRP gateway port requires frp_tls_server_name")
        return ""
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("FRP TLS server name must be a valid DNS hostname")
    labels = value.split(".")
    if len(labels) < 2 or not all(_HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("FRP TLS server name must be a valid DNS hostname")
    return (
        "transport:\n"
        "  tls:\n"
        "    enable: true\n"
        f'    serverName: "{value}"\n'
        "    disableCustomTLSFirstByte: true\n"
    )
