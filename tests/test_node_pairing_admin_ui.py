"""Pairing UI secret-handling and route-gating source invariants.

This complements frontend TypeScript production build and FastAPI tests.
No browsers, servers or live Node credentials are involved.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "frontend/src/components/NodePairingAction.tsx"
NODES = ROOT / "frontend/src/pages/Nodes.tsx"
SERVERS = ROOT / "frontend/src/pages/Servers.tsx"
API = ROOT / "panel/app/routers/node_pairing.py"


class PreviewUIStaticTest(unittest.TestCase):
    def test_secret_not_persisted_or_logged(self):
        source = UI.read_text()
        self.assertIn("setPairingCode(null)", source)
        self.assertIn("setExpiresAt(null)", source)
        self.assertIn("return () => controller.current?.abort()", source)
        self.assertIn("clearInterval(interval)", source)
        for forbidden in (
            "localStorage.setItem",
            "sessionStorage.setItem",
            "console.log",
            "console.error",
            "window.location.href",
            "history.pushState",
            "document.cookie",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_preview_admin_capability_and_explicit_confirmation(self):
        source = UI.read_text()
        self.assertIn("'/node-pairing/capabilities'", source)
        self.assertIn("'/node-pairing/issue'", source)
        self.assertIn("legacy_node_auth_enforced === false", source)
        self.assertIn("verified", source)
        self.assertIn("ttl_seconds: 600", source)
        self.assertIn("Pair (preview)", source)
        self.assertIn("does not secure the existing", source)

    def test_both_role_pages_share_same_modal_without_altering_registration(self):
        for path, role in ((NODES, "iran"), (SERVERS, "foreign")):
            with self.subTest(path=path):
                source = path.read_text()
                self.assertIn('NodePairingAction', source)
                self.assertIn('role="' + role + '" enabled={pairingPreviewEnabled}', source)
                self.assertIn("api.post('/nodes'", source)

    def test_backend_capability_is_authenticated_and_never_discloses_keys(self):
        source = API.read_text()
        self.assertIn('@router.get("/capabilities")', source)
        self.assertIn("Depends(auth.get_current_user)", source)
        self.assertIn('"pairing_preview_enabled": enabled', source)
        self.assertIn('"legacy_node_auth_enforced": False', source)
        self.assertIn('_no_store(response)', source)


if __name__ == "__main__":
    unittest.main()
