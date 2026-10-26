import base64
import unittest
from unittest.mock import patch

from app.uopti_route_broker_client import (
    BrokerForwardUnavailable,
    decode_intent_b64,
    forward_route_intent,
)


class FakeSocket:
    def __init__(self, response=b"PASS_ROUTE_ADDED\n"):
        self.response = response
        self.sent = []
        self.path = None
        self.timeout = None
        self.shutdown_how = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, value):
        self.timeout = value

    def connect(self, path):
        self.path = path

    def sendall(self, value):
        self.sent.append(value)

    def shutdown(self, how):
        self.shutdown_how = how

    def recv(self, _size):
        value, self.response = self.response, b""
        return value


class BrokerForwardTest(unittest.TestCase):
    def test_decode_accepts_only_canonical_bounded_base64(self):
        wire = b'{"audience":"u-opti:ir:xhttp-route:v1"}'
        self.assertEqual(decode_intent_b64(base64.b64encode(wire).decode()), wire)
        for value in ("", "%%%", base64.b64encode(b"x").decode() + "=", "YQ==\n"):
            with self.subTest(value=value), self.assertRaises(BrokerForwardUnavailable):
                decode_intent_b64(value)
        with self.assertRaises(BrokerForwardUnavailable):
            decode_intent_b64(base64.b64encode(b"x" * 4097).decode())

    def test_forward_sends_exact_wire_and_requires_exact_pass(self):
        wire = b'{"mac":"fixed","nonce":"123"}'
        fake = FakeSocket()
        with patch("app.uopti_route_broker_client.socket.socket", return_value=fake):
            forward_route_intent(wire, "/run/u-opti/smite/xhttp-broker.sock")
        self.assertEqual(fake.path, "/run/u-opti/smite/xhttp-broker.sock")
        self.assertEqual(fake.sent, [wire + b"\n"])
        self.assertEqual(fake.timeout, 6.0)

    def test_hold_and_ambiguous_empty_reply_fail_closed(self):
        for response in (b"HOLD\n", b"PASS_ROUTE_ADDED\nextra", b""):
            fake = FakeSocket(response)
            with patch("app.uopti_route_broker_client.socket.socket", return_value=fake):
                with self.subTest(response=response), self.assertRaises(BrokerForwardUnavailable):
                    forward_route_intent(b'{"intent":1}', "/run/broker.sock")

    def test_invalid_arguments_never_open_socket(self):
        with patch("app.uopti_route_broker_client.socket.socket") as create_socket:
            with self.assertRaises(BrokerForwardUnavailable):
                forward_route_intent(b"", "/run/broker.sock")
            with self.assertRaises(BrokerForwardUnavailable):
                forward_route_intent(b"x", "relative.sock")
            create_socket.assert_not_called()


if __name__ == "__main__":
    unittest.main()
