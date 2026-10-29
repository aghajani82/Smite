"""Explicit signed WSS policy for first-owner create and reapply.

The KH adapter independently pins transport to its configured Panel DNS/443.
No address is inferred from a request Host header or unsigned Node metadata.
"""
import re
from app.config import settings

LABEL = re.compile(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z')

def wss_host():
    if not settings.smite_frp_standard_wss:
        return ''
    host = settings.panel_domain
    if (settings.smite_panel_agent_auth_mode != 'signed'
            or settings.smite_engine_management_mode != 'managed'
            or not isinstance(host, str) or len(host) > 253
            or '.' not in host or not all(LABEL.fullmatch(p) for p in host.split('.'))):
        raise ValueError('Signed WSS requires managed authentication and configured Panel DNS')
    return host

def owner_spec(spec, tunnel_type):
    """Validate before DB/remote mutations; keep legacy mode unchanged."""
    if not wss_host():
        return dict(spec)
    if (tunnel_type != 'tcp' or spec.get('bind_port', 7000) != 7000
            or spec.get('local_ip', '127.0.0.1') != '127.0.0.1'
            or spec.get('frp_gateway_port', 443) != 443
            or spec.get('frp_tls_server_name', wss_host()) != wss_host()):
        raise ValueError('Signed WSS requires TCP, loopback target and the configured 443 endpoint')
    result = dict(spec)
    result.update(bind_port=7000, local_ip='127.0.0.1')
    return result

def server_address(node):
    return wss_host() or (node.node_metadata or {}).get('ip_address')
