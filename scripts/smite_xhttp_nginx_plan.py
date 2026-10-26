"""Pure, offline XHTTP Nginx route planner for signed Sanaei inbound facts.

IMPORTANT: This module NEVER writes Nginx files, reloads Nginx, manages
FRP, or grants root access. A later independently reviewed host-side
transaction controller must own config includes, backups and validation.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
import re
from typing import Any


class RouteAdmissionDenied(ValueError):
    """Fail closed on untrusted or colliding XHTTP route inputs."""


PATH = re.compile(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\Z")


@dataclass(frozen=True)
class RoutePlan:
    port: int
    path: str
    exact_location: str
    prefix_location: str
    snippet: str
    already_present: bool


def plan_xhttp_nginx_route(
    inbound: Mapping[str, Any],
    *,
    registered_routes: Mapping[str, int],
    frps_listener_ports: set[int],
) -> RoutePlan:
    """Plan a path-preserving loopback XHTTP proxy, no arbitrary Nginx text.

    Inputs MUST originate from trusted signed KH inventory and independent
    verified IR FRPS socket proof. registered_routes MUST be the complete,
    independently trusted Nginx location inventory; never assume missing.
    """
    if not isinstance(inbound, Mapping) or not isinstance(registered_routes, Mapping):
        raise RouteAdmissionDenied("Trusted inbound and route inventory required")
    port = inbound.get("port")
    path = inbound.get("path")
    if (type(port) is not int or not 1024 <= port <= 65535
            or not isinstance(path, str) or len(path) > 128
            or not PATH.fullmatch(path) or not path.startswith(f"/{port}/")
            or inbound.get("listen") != "127.0.0.1"
            or inbound.get("network") != "xhttp"
            or inbound.get("protocol") != "vless"
            or inbound.get("enabled") is not True):
        raise RouteAdmissionDenied("Untrusted XHTTP inbound")
    if (not isinstance(frps_listener_ports, set)
            or any(type(x) is not int for x in frps_listener_ports)
            or 7000 not in frps_listener_ports
            or port not in frps_listener_ports):
        raise RouteAdmissionDenied("Verified FRPS singleton proxy not present")

    # A route may be retried only when the *exact* same destination is already
    # recorded. Refuse a second route for a port or any prefix-shadow collision.
    already = False
    for existing_path, existing_port in registered_routes.items():
        if (not isinstance(existing_path, str) or type(existing_port) is not int):
            raise RouteAdmissionDenied("Existing route inventory invalid")
        if existing_path == path and existing_port == port:
            already = True
        elif existing_path == path or existing_port == port:
            raise RouteAdmissionDenied("Duplicate XHTTP route destination")
        elif existing_path.startswith(path + "/") or path.startswith(existing_path + "/"):
            raise RouteAdmissionDenied("Nginx XHTTP prefix collision")

    directives = (
        f"    proxy_pass http://127.0.0.1:{port};\n"
        "    proxy_http_version 1.1;\n"
        "    proxy_set_header Host $host;\n"
        "    proxy_set_header X-Forwarded-Proto $scheme;\n"
        "    proxy_buffering off;\n"
        "    proxy_request_buffering off;\n"
        "    proxy_connect_timeout 10s;\n"
        "    proxy_read_timeout 3600s;\n"
        "    proxy_send_timeout 3600s;\n"
    )
    snippet = (
        f"# Smite managed XHTTP port {port} (path preserved)\n"
        f"location = {path} {{\n{directives}}}\n"
        f"location ^~ {path}/ {{\n{directives}}}\n"
    )
    return RoutePlan(port, path, path, path + "/", snippet, already)
