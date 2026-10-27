"""Actual-function offline regression for signed managed FRP startup/timer."""
import ast
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]

class Tunnel:
    status = "active"
    id = "live-owner-45121"
    core = "frp"
    type = "tcp"
    node_id = "node-ir"
    spec = {"ports": [45121], "bind_port": 7000, "token": "TEST_ONLY"}

class Node:
    id = "node-ir"

class Query:
    def where(self, _condition):
        return self

def select(_model):
    return Query()

class Result:
    def scalars(self):
        return self
    def all(self):
        return [Tunnel()]

class Session:
    def __init__(self):
        self.writes = 0
    async def __aenter__(self):
        return self
    async def __aexit__(self, *_args):
        pass
    async def execute(self, _query):
        return Result()
    async def commit(self):
        self.writes += 1

def isolated_function(path, name, *, klass=None, globals_=None):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    block = tree.body
    if klass:
        block = next(x.body for x in block if isinstance(x, ast.ClassDef) and x.name == klass)
    fn = next(x for x in block if isinstance(x, ast.AsyncFunctionDef) and x.name == name)
    module = ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[]))
    env = {} if globals_ is None else dict(globals_)
    exec(compile(module, str(ROOT / path), "exec"), env)
    return env[name]

class SignedManagedFRPNoAutoApply(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.settings = types.SimpleNamespace(
            smite_engine_management_mode="managed",
            smite_panel_agent_auth_mode="signed",
        )
        self.session = Session()
        self.calls = []
        calls = self.calls
        class Client:
            async def send_to_node(self, **kwargs):
                calls.append(kwargs)
                raise AssertionError("Unexpected signed Node Apply")
        self.base = {
            "AsyncSessionLocal": lambda: self.session,
            "Tunnel": Tunnel,
            "select": select,
            "NodeClient": Client,
            "settings": self.settings,
            "logger": Mock(),
        }

    async def test_panel_startup_skips_existing_signed_managed_owner(self):
        fn = isolated_function("panel/main.py", "_restore_node_tunnels", globals_=self.base)
        await fn()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.session.writes, 0)

    async def test_timer_skips_existing_signed_managed_owner(self):
        modules = {}
        for name in ("app", "app.config", "app.models", "app.routers", "app.routers.tunnels",
                     "fastapi", "starlette", "starlette.requests", "starlette.datastructures"):
            module = types.ModuleType(name)
            if name in ("app", "app.routers", "starlette"):
                module.__path__ = []
            modules[name] = module
        modules["app.config"].settings = self.settings
        modules["app.models"].Node = Node
        modules["app.routers.tunnels"].prepare_frp_spec_for_node = lambda *args: None
        modules["fastapi"].Request = object
        modules["starlette.requests"].Request = lambda **kwargs: object()
        class Headers:
            def __init__(self, *_args):
                self.raw = []
        modules["starlette.datastructures"].Headers = Headers
        fn = isolated_function(
            "panel/app/tunnel_reapply_manager.py", "_reapply_all_tunnels",
            klass="TunnelReapplyManager", globals_=self.base,
        )
        with patch.dict(sys.modules, modules):
            await fn(object())
        self.assertEqual(self.calls, [])
        self.assertEqual(self.session.writes, 0)

    def test_guards_cover_only_signed_managed_frp(self):
        for path, name in (
            ("panel/main.py", "startup"),
            ("panel/app/tunnel_reapply_manager.py", "timer"),
        ):
            source = (ROOT / path).read_text()
            self.assertIn('tunnel.core == "frp"', source, name)
            self.assertIn('settings.smite_engine_management_mode == "managed"', source, name)
            self.assertIn('settings.smite_panel_agent_auth_mode == "signed"', source, name)

if __name__ == "__main__":
    unittest.main()
