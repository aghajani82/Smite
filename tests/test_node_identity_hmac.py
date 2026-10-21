"""Unit tests for the Phase 1 Node ↔ Panel request signature envelope.

No containers, database, network, or live tunnels. This does NOT assert
that application routes enforce authentication: they do not, yet.
"""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ROOT / "panel/app/node_auth.py",
    ROOT / "node/app/node_auth.py",
)


def load_module(path, unique_name):
    spec = importlib.util.spec_from_file_location(unique_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PANEL = load_module(SOURCES[0], "smite_panel_auth_envelope")
NODE = load_module(SOURCES[1], "smite_node_auth_envelope")


class SignedEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.key = b"randomly-provisioned-node-key-32-bytes-1234567890"
        self.node_id = "node-8790c6f0"
        self.now = 1_850_000_000
        self.body = b'{"core":"backhaul","tunnel_id":"abc"}'
        self.target = "/api/agent/tunnels/apply"
        self.headers = NODE.sign_request(
            secret=self.key, node_id=self.node_id, method="POST",
            target=self.target, body=self.body, timestamp=self.now,
            nonce="a" * 32,
        )
        self.replay = PANEL.NonceWindow()

    def verified(self, **changes):
        args = {
            "secret": self.key,
            "node_id": self.node_id,
            "method": "POST",
            "target": self.target,
            "body": self.body,
            "headers": self.headers,
            "replay": self.replay,
            "now": self.now,
        }
        args.update(changes)
        return PANEL.verify_request(**args)

    def test_provisioned_node_can_sign_and_panel_can_verify(self):
        self.assertTrue(self.verified())

    def test_single_signed_envelope_is_accepted_at_most_once(self):
        self.assertTrue(self.verified())
        self.assertFalse(self.verified())

    def test_payload_method_path_and_node_id_are_bound(self):
        for field, value in (
            ("body", b'{"core":"frp","tunnel_id":"abc"}'),
            ("method", "DELETE"),
            ("target", "/api/agent/tunnels/remove"),
            ("node_id", "node-11111111"),
            ("secret", b"another-randomly-provisioned-secret-xxxxxxxx"),
        ):
            with self.subTest(field=field):
                self.assertFalse(self.verified(**{field: value}))

    def test_nonce_timestamp_and_signature_integrity(self):
        variants = (
            {"x-smite-nonce": "b" * 32},
            {"x-smite-timestamp": str(self.now + 1)},
            {"x-smite-signature": "0" * 64},
            {"x-smite-node-id": "node-11111111"},
            {"x-smite-signature": ""},
        )
        for replacements in variants:
            with self.subTest(replacements=replacements):
                h = dict(self.headers)
                h.update(replacements)
                self.assertFalse(self.verified(headers=h))
        self.assertTrue(self.verified())

    def test_clock_window_is_bounded_and_signed_at_is_not_reusable(self):
        self.assertFalse(self.verified(now=self.now + 91))
        self.assertFalse(self.verified(now=self.now - 91))
        self.assertTrue(self.verified(now=self.now + 90))
        self.assertFalse(self.verified(now=self.now + 90))

    def test_query_string_must_be_identical(self):
        target = "/api/nodes?role=iran&trace=1"
        headers = NODE.sign_request(
            secret=self.key, node_id=self.node_id, method="POST",
            target=target, body=b"{}", timestamp=self.now, nonce="d" * 32,
        )
        window = PANEL.NonceWindow()
        self.assertFalse(PANEL.verify_request(
            secret=self.key, node_id=self.node_id, method="POST",
            target="/api/nodes?role=iran", body=b"{}", headers=headers,
            replay=window, now=self.now,
        ))
        self.assertTrue(PANEL.verify_request(
            secret=self.key, node_id=self.node_id, method="POST",
            target=target, body=b"{}", headers=headers,
            replay=window, now=self.now,
        ))

    def test_header_keys_can_be_case_insensitive(self):
        headers = {k.lower(): v for k, v in self.headers.items()}
        self.assertTrue(self.verified(headers=headers))

    def test_replay_limit_fails_closed_instead_of_eviction(self):
        cache = PANEL.NonceWindow(max_entries=1)
        self.assertTrue(self.verified(replay=cache))
        new = NODE.sign_request(
            secret=self.key, node_id=self.node_id, method="POST",
            target=self.target, body=self.body, timestamp=self.now,
            nonce="e" * 32,
        )
        self.assertFalse(self.verified(headers=new, replay=cache))

    def test_concurrent_attempts_allow_exactly_one(self):
        with ThreadPoolExecutor(max_workers=24) as pool:
            outcomes = list(pool.map(lambda _: self.verified(), range(100)))
        self.assertEqual(outcomes.count(True), 1)

    def test_refuse_invalid_or_absent_node_key(self):
        with self.assertRaises(PANEL.NodeAuthError):
            PANEL.sign_request(
                secret=b"", node_id=self.node_id, method="POST",
                target=self.target,
            )

    def test_modules_are_identical_and_no_wiring_claimed(self):
        self.assertEqual(SOURCES[0].read_bytes(), SOURCES[1].read_bytes())
        # Only cryptographic primitive is shipped in this milestone:
        # server and agent route migration MUST be a later security-reviewed PR.
        self.assertNotIn("node_auth.verify_request(", (ROOT / "panel/main.py").read_text())
        self.assertNotIn("node_auth.verify_request(", (ROOT / "node/main.py").read_text())


if __name__ == "__main__":
    unittest.main()
