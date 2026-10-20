"""Registry pair candidate remains inert and ties TWO distinct digests to one SHA."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/create-registry-pair.py"
spec = importlib.util.spec_from_file_location("registry_pair_manifest", SCRIPT)
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)
SHA = "a" * 40
PANEL = "sha256:" + "b" * 64
NODE = "sha256:" + "c" * 64

class RegistryPairManifestTest(unittest.TestCase):
    def good(self, **override):
        args = dict(source_sha=SHA, publish_ref="refs/tags/v2.0.0-rc.0",
                    version="2.0.0-rc.0", panel_digest=PANEL, node_digest=NODE)
        args.update(override)
        return pair.build_pair(**args)

    def test_matching_sources_roles_digest_and_no_activation(self):
        manifest = self.good()
        self.assertEqual(manifest["source_commit"], SHA)
        self.assertEqual(manifest["source_repo"], "aghajani82/Smite")
        self.assertEqual(set(manifest["images"]), {"panel", "node"})
        self.assertEqual(manifest["images"]["panel"], "ghcr.io/aghajani82/smite-panel@" + PANEL)
        self.assertEqual(manifest["images"]["node"], "ghcr.io/aghajani82/smite-node@" + NODE)
        self.assertIs(manifest["activation_allowed"], False)
        self.assertIs(manifest["release_approved"], False)

    def test_mixed_sources_and_invalid_refs_hold(self):
        for bad in [
            {"source_sha": "bad"}, {"source_sha": "A" * 40},
            {"publish_ref": "refs/heads/main"},
            {"publish_ref": "refs/tags/v2.0.1"},
            {"version": "latest"}, {"version": "2.0.0+dirty"},
            {"panel_digest": NODE}, {"panel_digest": "sha256:" + "x" * 64},
            {"node_digest": "latest"}, {"node_digest": "sha256:" + "f" * 32},
        ]:
            with self.subTest(bad=bad), self.assertRaises(pair.PairHold):
                self.good(**bad)

    def test_cli_is_deterministic_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "pair.json"
            cmd = [sys.executable, "-B", str(SCRIPT),
                   "--source-sha", SHA, "--publish-ref", "refs/tags/v2.0.0-rc.0",
                   "--version", "2.0.0-rc.0", "--panel-digest", PANEL,
                   "--node-digest", NODE, "--output", str(out)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ACTIVATION_ALLOWED=NO", result.stdout)
            self.assertEqual(json.loads(out.read_bytes()), self.good())
            again = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(json.loads(out.read_bytes()), self.good())

    def test_publisher_requires_both_signed_jobs_before_pair_artifact(self):
        workflow = (ROOT / ".github/workflows/publish-images.yml").read_text()
        section = workflow.split("\n  registry-pair-manifest:\n", 1)[1]
        self.assertIn("needs: [prepare, build-panel, build-node]", section)
        self.assertIn("github.ref_type == 'tag'", section)
        self.assertIn("needs.build-panel.outputs.digest", section)
        self.assertIn("needs.build-node.outputs.digest", section)
        self.assertIn("scripts/create-registry-pair.py", section)
        self.assertIn("actions/upload-artifact@v4", section)
        self.assertEqual(workflow.count("push-by-digest=true,name-canonical=true,push=true"), 2)
        self.assertIn("retention-days: 7", section)
        self.assertIn("ref: ${{ github.sha }}", section)
        for role in ("panel", "node"):
            block = workflow.split("\n  build-" + role + ":\n", 1)[1].split("\n  build-", 1)[0]
            self.assertIn("digest: ${{ steps.pushed-" + role + ".outputs.digest }}", block)

if __name__ == "__main__":
    unittest.main(verbosity=2)
