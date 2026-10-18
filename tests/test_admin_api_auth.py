"""Security regression checks for Smite administrative API routes.

No production services, Node registration or tunnel operations are started.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel"))

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from main import app
from app.routers.auth import get_current_user


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

    def test_existing_bootstrap_and_health_routes_not_blanket_blocked(self):
        # These endpoints require separate node authentication work.
        for path in (
            "/api/auth/login",
            "/api/status",
            "/api/status/version",
            "/api/nodes",
            "/api/panel/ca",
            "/api/panel/ca/server",
        ):
            with self.subTest(path=path):
                matches = [route for route in routes_matching(path) if route.path == path]
                self.assertTrue(matches)
                self.assertFalse(any(requires_admin(route) for route in matches))

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
