"""Fail-closed FRP WSS/443 target for signed managed Smite Panel.

Only the reviewed Panel domain is authoritative. Never use an arbitrary
request header, spoofable node metadata, caller-provided host or legacy
fallback to bypass the historic missing-IP guard. Non-WSS FRP remains
unchanged and must still have the Iran Node's registered IP.
"""
from __future__ import annotations

import re

_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class FrpWssTargetError(ValueError):
    pass


def resolve_frp_target(
    iran_ip: str | None,
    *,
    wss_enabled: bool,
    signed_panel: bool,
    managed_engines: bool,
    panel_domain: str,
    bind_port: object,
    tunnel_type: str,
) -> str | None:
    """Resolve trusted FRP control address without changing legacy behavior."""
    if not wss_enabled:
        return iran_ip or None
    if not signed_panel or not managed_engines:
        raise FrpWssTargetError("FRP WSS requires signed managed Panel mode")
    if type(bind_port) not in (str, int) or str(bind_port) != "7000":
        raise FrpWssTargetError("FRP WSS requires bind port 7000")
    if tunnel_type != "tcp":
        raise FrpWssTargetError("FRP WSS/443 trial supports TCP only")
    if not isinstance(panel_domain, str) or len(panel_domain) > 253:
        raise FrpWssTargetError("FRP WSS requires trusted PANEL_DOMAIN")
    if (
        not panel_domain
        or "://" in panel_domain or ":" in panel_domain
        or panel_domain != panel_domain.strip()
        or len(panel_domain.split(".")) < 2
        or not all(_LABEL.fullmatch(part) for part in panel_domain.split("."))
    ):
        raise FrpWssTargetError("FRP WSS requires trusted PANEL_DOMAIN")
    return panel_domain
