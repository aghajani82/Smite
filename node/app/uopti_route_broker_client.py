"""Narrow IR Node to U-OPTI local route broker transport.

This module forwards an already signed route intent unchanged. It does not
hold the broker HMAC key, create grants, retry, or log request contents.
"""
from __future__ import annotations

import base64
import binascii
import socket


MAX_INTENT_BYTES = 4096
SOCKET_RESPONSE = b"PASS_ROUTE_ADDED\n"


class BrokerForwardUnavailable(RuntimeError):
    """The local broker did not confirm a completed route transaction."""


def decode_intent_b64(value: str) -> bytes:
    """Decode one canonical base64 envelope from the signed Panel request."""
    if type(value) is not str or not value or len(value) > 4 * ((MAX_INTENT_BYTES + 2) // 3):
        raise BrokerForwardUnavailable("INVALID_INTENT")
    try:
        wire = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise BrokerForwardUnavailable("INVALID_INTENT") from exc
    if (not wire or len(wire) > MAX_INTENT_BYTES
            or base64.b64encode(wire).decode("ascii") != value):
        raise BrokerForwardUnavailable("INVALID_INTENT")
    return wire


def forward_route_intent(wire: bytes, socket_path: str) -> None:
    """Forward one signed envelope; ambiguous failures are surfaced, never retried."""
    if (type(wire) is not bytes or not 0 < len(wire) <= MAX_INTENT_BYTES
            or type(socket_path) is not str or not socket_path.startswith("/")):
        raise BrokerForwardUnavailable("BROKER_NOT_CONFIGURED")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(6.0)
            client.connect(socket_path)
            client.sendall(wire + b"\n")
            client.shutdown(socket.SHUT_WR)
            response = bytearray()
            while len(response) <= 64 and b"\n" not in response:
                part = client.recv(65 - len(response))
                if not part:
                    break
                response.extend(part)
    except (OSError, TimeoutError) as exc:
        raise BrokerForwardUnavailable("BROKER_UNAVAILABLE_OR_UNCERTAIN") from exc
    if bytes(response) != SOCKET_RESPONSE:
        raise BrokerForwardUnavailable("BROKER_HOLD_OR_UNCERTAIN")
