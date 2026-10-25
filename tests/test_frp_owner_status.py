"""Offline signed runtime FRPS owner evidence: no leak, no write, no network."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import psutil

ROOT=Path(__file__).resolve().parents[1]
p=ROOT/"node/app/frp_owner_status.py"
spec=importlib.util.spec_from_file_location("frp_owner_status_tests", p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def conn(pid,port=7000,ip="127.0.0.1",status=psutil.CONN_LISTEN):
    return SimpleNamespace(pid=pid,laddr=SimpleNamespace(ip=ip,port=port),status=status)

def manager(pid=120, mode="server", alive=True):
    proc=SimpleNamespace(pid=pid,poll=lambda: None if alive else 1)
    adapter=SimpleNamespace(name="frp", processes={"owner-tunnel":proc})
    return SimpleNamespace(
        tunnel_configs={"owner-tunnel":{"core":"frp","spec":{"mode":mode,"bind_port":7000,"token":"DO_NOT_LEAK"}}},
        active_tunnels={"owner-tunnel":adapter},
    )

class FrpsOwnerStatusTests(unittest.TestCase):
    def test_pid_plus_loopback_port_proves_owner_not_db_flag(self):
        records=mod.active_signed_frps_owners(manager(),listeners=[conn(120)])
        self.assertEqual(records,[{"tunnel_id":"owner-tunnel","control_port":7000}])
        self.assertNotIn("DO_NOT_LEAK",repr(records))

    def test_wrong_pid_ip_port_not_owner(self):
        for listeners in ([conn(999)], [conn(120,ip="0.0.0.0")], [conn(120,port=7001)], [], [conn(120,status="ESTABLISHED")]):
            with self.subTest(listeners=listeners):
                self.assertEqual(mod.active_signed_frps_owners(manager(),listeners=listeners),[])

    def test_dead_process_missing_tracking_does_not_pass(self):
        self.assertEqual(mod.active_signed_frps_owners(manager(alive=False),listeners=[conn(120)]),[])
        state=manager();state.active_tunnels.clear()
        self.assertEqual(mod.active_signed_frps_owners(state,listeners=[conn(120)]),[])

    def test_psutil_denied_fails_closed(self):
        with patch.object(mod.psutil,"net_connections",side_effect=psutil.AccessDenied()):
            self.assertEqual(mod.active_signed_frps_owners(manager()),[])

    def test_no_legacy_anonymous_owner_endpoint(self):
        source=(ROOT/"node/app/routers/agent.py").read_text()
        self.assertIn('@router.get("/frp/owners")',source)
        self.assertIn('if settings.smite_agent_auth_mode != "strict":',source)
        self.assertIn('APIRouter(dependencies=[Depends(require_agent_auth)])',source)

    def test_panel_cannot_use_legacy_fallback_for_owner_probe(self):
        source=(ROOT/"panel/app/node_client.py").read_text()
        self.assertIn('target="/api/agent/frp/owners"',source)
        self.assertIn('settings.smite_panel_agent_auth_mode != "signed"',source)

if __name__=="__main__":
    unittest.main()
