"""Security regression checks for Smite administrative API routes.

No production services, Node registration or tunnel operations are started.
"""
import ast
import sys
import unittest
from pathlib import Path

PANEL_DIR = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL_DIR))

from fastapi import FastAPI, Depends
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from app.routers import auth, tunnels, logs, core_health
from app.routers import settings as settings_router
from app.routers.auth import get_current_user

# Importing panel/main.py in a CI host initializes production GOST managers
# and writes under /app. Instead, exercise the same real router objects on
# an inert ASGI app, and separately assert that the production main.py uses
# the authenticated mounting policy.
app = FastAPI()
admin_only = [Depends(get_current_user)]
app.include_router(auth.router, prefix="/api/auth")
app.include_router(tunnels.router, prefix="/api/tunnels", dependencies=admin_only)
app.include_router(settings_router.router, dependencies=admin_only)
app.include_router(logs.router, prefix="/api/logs", dependencies=admin_only)
app.include_router(core_health.router, prefix="/api/core-health", dependencies=admin_only)


def routes_matching(prefix):
    return [
        route for route in app.routes
        if isinstance(route, APIRoute)
        and (route.path == prefix or route.path.startswith(prefix + "/"))
    ]


def requires_admin(route):
    return any(dependency.call is get_current_user for dependency in route.dependant.dependencies)


class AdminAPIAuthorization(unittest.TestCase):
    def test_every_admin_route_has_server_side_auth(self):
        for prefix in ("/api/tunnels", "/api/settings", "/api/logs", "/api/core-health"):
            with self.subTest(prefix=prefix):
                routes = routes_matching(prefix)
                self.assertTrue(routes, "Expected at least one route")
                for route in routes:
                    self.assertTrue(
                        requires_admin(route),
                        f"Missing auth dependency on {sorted(route.methods)} {route.path}",
                    )

    def test_production_router_wiring_preserves_bootstrap_routes(self):
        tree = ast.parse((PANEL_DIR / "main.py").read_text(encoding="utf-8"))
        app_calls = {}
        admin_assign = None
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                if any(isinstance(t, ast.Name) and t.id == "admin_only" for t in stmt.targets):
                    admin_assign = ast.unparse(stmt.value)
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "include_router":
                    if call.args:
                        app_calls[ast.unparse(call.args[0])] = {
                            k.arg: ast.unparse(k.value) for k in call.keywords
                        }
        self.assertEqual(admin_assign, "[Depends(auth.get_current_user)]")
        for router in ("tunnels.router", "settings_router.router", "logs.router", "core_health.router"):
            self.assertEqual(app_calls[router].get("dependencies"), "admin_only", router)
        for router in ("auth.router", "panel.router", "nodes.router", "status.router"):
            self.assertNotIn("dependencies", app_calls[router], router)

    def test_anonymous_admin_requests_are_denied(self):
        # Do not use a TestClient context manager, as it would run the
        # production lifespan and start node/tunnel background services.
        client = TestClient(app)
        for path in (
            "/api/tunnels",
            "/api/settings",
            "/api/logs",
            "/api/core-health/health",
        ):
            with self.subTest(path=path):
                response = client.get(path)
                self.assertIn(response.status_code, (401, 403))
                self.assertNotIn("access_token", response.text)

    def test_invalid_bearer_token_is_denied(self):
        client = TestClient(app)
        response = client.get("/api/settings", headers={"Authorization": "Bearer invalid"})
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
