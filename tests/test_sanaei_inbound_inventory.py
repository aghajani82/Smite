"""Offline adversarial tests; real Sanaei, Docker, FRP and network are untouched."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "node"))
from app.sanaei_inbound_inventory import (
    list_approved_xhttp_inbounds, SanaeiInventoryUnavailable,
)


class SanaeiInboundInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "x-ui.db"
        with sqlite3.connect(self.path) as con:
            con.execute("""CREATE TABLE inbounds (
                port INTEGER, listen TEXT, protocol TEXT,
                stream_settings TEXT, enable INTEGER, settings TEXT
            )""")
        self.path.chmod(0o600)

    def inbound(self, port=49328, *, path=None, listen="127.0.0.1",
                network="xhttp", protocol="vless", enable=1,
                stream_override=None):
        stream = stream_override if stream_override is not None else {
            "network": network,
            "xhttpSettings": {"path": path or f"/{port}/sso"},
        }
        with sqlite3.connect(self.path) as con:
            con.execute("INSERT INTO inbounds VALUES (?,?,?,?,?,?)", (
                port, listen, protocol, json.dumps(stream), enable,
                json.dumps({"clients": [{"id": "NEVER-LEAK-UUID-1234"}]}),
            ))

    def test_only_trusted_enabled_xhttp_ignores_client_secrets(self):
        self.inbound(49328)
        self.inbound(45121, path="/45121/www")
        self.inbound(45000, network="ws")
        self.inbound(46111, enable=0)
        result = list_approved_xhttp_inbounds(str(self.path))
        self.assertEqual([x["port"] for x in result], [45121, 49328])
        self.assertEqual(result[0]["path"], "/45121/www")
        self.assertEqual(result[1]["path"], "/49328/sso")
        self.assertEqual(set(result[0]), {
            "port", "listen", "protocol", "network", "path", "enabled",
        })
        self.assertNotIn("NEVER-LEAK-UUID", repr(result))
        self.assertNotIn("settings", repr(result))

    def test_missing_db_schema_symlink_and_group_write_fail_closed(self):
        with self.assertRaises(SanaeiInventoryUnavailable):
            list_approved_xhttp_inbounds(str(self.path.parent / "missing.db"))
        wrong = self.path.parent / "fake.db"
        wrong.symlink_to(self.path)
        with self.assertRaises(SanaeiInventoryUnavailable):
            list_approved_xhttp_inbounds(str(wrong))
        self.path.chmod(0o660)
        with self.assertRaises(SanaeiInventoryUnavailable):
            list_approved_xhttp_inbounds(str(self.path))
        self.path.chmod(0o600)
        with sqlite3.connect(self.path) as con:
            con.execute("DROP TABLE inbounds")
        with self.assertRaises(SanaeiInventoryUnavailable):
            list_approved_xhttp_inbounds(str(self.path))

    def test_non_loopback_and_unsafe_paths_are_rejected_not_sanitized(self):
        for options in (
            {"listen": "0.0.0.0"},
            {"path": "/49328/../sso"},
            {"path": "/49328/sso?token=sensitive"},
            {"path": "/api/sso"},
            {"path": "/49328/sso/"},
            {"port": 70000},
        ):
            with self.subTest(options=options):
                with sqlite3.connect(self.path) as con:
                    con.execute("DELETE FROM inbounds")
                self.inbound(**options)
                with self.assertRaises(SanaeiInventoryUnavailable):
                    list_approved_xhttp_inbounds(str(self.path))

    def test_conflicting_port_and_malformed_transport_fail_closed(self):
        self.inbound()
        self.inbound()
        with self.assertRaises(SanaeiInventoryUnavailable):
            list_approved_xhttp_inbounds(str(self.path))

    def test_compose_mount_is_opt_in_by_path_and_read_only(self):
        compose = (ROOT / "node/docker-compose.yml").read_text()
        expected_mount = "${SMITE_SANAEI_DB_HOST_PATH:-/var/lib/u-opti/smite-sanaei-empty}:/run/smite-sanaei-ro:ro"
        self.assertIn(expected_mount, compose)
        self.assertIn("SMITE_SANAEI_INVENTORY_ENABLED=${SMITE_SANAEI_INVENTORY_ENABLED:-false}", compose)
        self.assertIn("SMITE_SANAEI_DB_PATH=/run/smite-sanaei-ro/x-ui.db", compose)
        self.assertNotIn("/opt/3x-ui/instances/01/db/x-ui.db", compose)
        with sqlite3.connect(self.path) as con:
            con.execute("DELETE FROM inbounds")
        self.inbound(stream_override={"network": "xhttp", "xhttpSettings": {}})
        with self.assertRaises(SanaeiInventoryUnavailable):
            list_approved_xhttp_inbounds(str(self.path))


if __name__ == "__main__":
    unittest.main()
