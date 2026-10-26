"""Smite Panel offline route-intent issuer tests (no Agent or host calls)."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))
from app.xhttp_route_intent import (
    ApprovedRouteBinding, RouteIntentHold, sign_route_intent,
)

KEY = bytes(range(32))
STAMP = 1_798_000_000


def binding():
    return ApprovedRouteBinding(
        ir_node="node-ir-0001",
        kh_node="node-kh-0001",
        owner="trial-frp-45121",
        child="trial-frp-49328",
        lease="lease-49328-00001",
        port=49328,
        path="/49328/sso",
        owner_proof_sha256="a" * 64,
        kh_inventory_sha256="b" * 64,
    )


class RouteIntentIssuerTests(unittest.TestCase):
    def issue(self, b=None):
        with patch("app.xhttp_route_intent.secrets.token_hex",
                   return_value="c" * 32) as nonce:
            raw = sign_route_intent(b or binding(), dedicated_broker_key=KEY, now=STAMP)
            nonce.assert_called_once_with(16)
        return raw

    def test_exact_wire_schema_canonical_and_mac_for_broker(self):
        wire = self.issue()
        record = json.loads(wire)
        self.assertEqual(set(record), {
            "schema", "audience", "action", "ir_node", "kh_node",
            "owner", "child", "lease", "port", "path", "owner_proof_sha256",
            "kh_inventory_sha256", "issued_at", "expires_at", "nonce", "mac",
        })
        self.assertEqual(record["audience"], "u-opti:ir:xhttp-route:v1")
        self.assertEqual(record["action"], "create")
        self.assertEqual(record["expires_at"] - record["issued_at"], 30)
        self.assertEqual(record["nonce"], "c" * 32)
        self.assertEqual(record["port"], 49328)
        self.assertEqual(record["path"], "/49328/sso")
        self.assertEqual(wire, json.dumps(record, ensure_ascii=True,
                                        sort_keys=True, separators=(",", ":")).encode("ascii"))
        sig = record.pop("mac")
        canonical = json.dumps(record, ensure_ascii=True, sort_keys=True,
                               separators=(",", ":")).encode("ascii")
        self.assertEqual(sig, hmac.new(KEY, canonical, hashlib.sha256).hexdigest())
        self.assertNotIn(b"token", wire)
        self.assertNotIn(b"uuid", wire)

    def test_wrong_binding_port_path_credentials_and_evidence_refused(self):
        for updates in (
            {"ir_node": "x"},
            {"owner": ""},
            {"lease": "short"},
            {"port": 7000, "path": "/7000/control"},
            {"port": True},
            {"port": 60000, "path": "/49328/sso"},
            {"path": "/49328/../sso"},
            {"path": "/49328/sso/"},
            {"path": "/49328/sso?x=1"},
            {"owner_proof_sha256": "not-verified"},
            {"kh_inventory_sha256": "q" * 64},
        ):
            with self.subTest(updates=updates), self.assertRaises(RouteIntentHold):
                self.issue(replace(binding(), **updates))

    def test_different_valid_node_is_bound_into_hmac_but_requires_root_grant(self):
        # A syntactically valid alternate Node may be signed, but is NEVER
        # authorized by the issuer. U-OPTI's independent TrustedGrant must
        # reject any IR/KH identity mismatch before touching Nginx.
        first = self.issue()
        second = self.issue(replace(binding(), ir_node="other-ir-0001"))
        self.assertNotEqual(first, second)
        self.assertEqual(json.loads(second)["ir_node"], "other-ir-0001")
        self.assertNotEqual(json.loads(first)["mac"], json.loads(second)["mac"])

    def test_dedicated_key_and_server_timestamp_required(self):
        for key in (b"", b"b" * 16, b"b" * 64, "key"):
            with self.subTest(key=key), self.assertRaises(RouteIntentHold):
                sign_route_intent(binding(), dedicated_broker_key=key, now=STAMP)
        for now in (-1, True, 2**63, 3.14):
            with self.subTest(now=now), self.assertRaises(RouteIntentHold):
                sign_route_intent(binding(), dedicated_broker_key=KEY, now=now)
        with self.assertRaises(RouteIntentHold):
            sign_route_intent(None, dedicated_broker_key=KEY, now=STAMP)

    def test_secure_random_nonce_is_not_read_from_user_supplied_binding(self):
        a, b = self.issue(), self.issue()
        self.assertEqual(a, b)  # deterministic mock for this test only
        with patch("app.xhttp_route_intent.secrets.token_hex", side_effect=[
            "c" * 32, "d" * 32,
        ]):
            c = sign_route_intent(binding(), dedicated_broker_key=KEY, now=STAMP)
            d = sign_route_intent(binding(), dedicated_broker_key=KEY, now=STAMP)
        self.assertNotEqual(c, d)
        with patch("app.xhttp_route_intent.secrets.token_hex", return_value="invalid"):
            with self.assertRaises(RouteIntentHold):
                sign_route_intent(binding(), dedicated_broker_key=KEY, now=STAMP)


if __name__ == "__main__":
    unittest.main()
