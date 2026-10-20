"""Pure source-label provenance regression: no Docker or release actions."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "tests/stage15_image_revision_gate.py"
spec = importlib.util.spec_from_file_location("stage15_revision_gate", MODULE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SOURCE = "b" * 40
PANEL_ID = "sha256:" + "c" * 64
NODE_ID = "sha256:" + "d" * 64


def record(image_id, source=SOURCE, version="2.0.0-rc.0"):
    return {
        "Id": image_id,
        "Config": {"Labels": {
            gate.REVISION_LABEL: source,
            gate.VERSION_LABEL: version,
        }},
    }


class RevisionGateTest(unittest.TestCase):
    def good(self):
        return [record(PANEL_ID), record(NODE_ID)]

    def test_real_pair_exact_source_and_distinct_id(self):
        self.assertEqual(gate.inspect_pair(images=self.good(), source_sha=SOURCE),
                         (PANEL_ID, NODE_ID))

    def test_wrong_source_on_either_role_fails(self):
        for i in (0, 1):
            images = self.good()
            images[i]["Config"]["Labels"][gate.REVISION_LABEL] = "e" * 40
            with self.subTest(role=i), self.assertRaises(gate.ImageRevisionHold):
                gate.inspect_pair(images=images, source_sha=SOURCE)

    def test_missing_revision_and_wrong_version_fails(self):
        for i in (0, 1):
            images = self.good()
            images[i]["Config"]["Labels"].pop(gate.REVISION_LABEL)
            with self.subTest(missing_role=i), self.assertRaises(gate.ImageRevisionHold):
                gate.inspect_pair(images=images, source_sha=SOURCE)
            images = self.good()
            images[i]["Config"]["Labels"][gate.VERSION_LABEL] = "latest"
            with self.subTest(version_role=i), self.assertRaises(gate.ImageRevisionHold):
                gate.inspect_pair(images=images, source_sha=SOURCE)

    def test_duplicate_id_malformed_records_and_invalid_sha_fail(self):
        bad = [self.good()[0], record(PANEL_ID)]
        for images, sha in [
            (bad, SOURCE), ([self.good()[0]], SOURCE),
            ({"panel": self.good()[0]}, SOURCE),
            (self.good(), "wrong"), (self.good(), SOURCE.upper()),
            (self.good()[::-1], SOURCE),
        ]:
            # Swapping 2 good images alone is not distinguishable from labels;
            # the workflow supplies docker inspect in explicit Panel/Node order.
            if isinstance(images, list) and len(images) == 2 and (
                images[0]["Id"] == NODE_ID and images[1]["Id"] == PANEL_ID
            ):
                continue
            with self.subTest(sha=sha, images=str(images)[:80]):
                with self.assertRaises(gate.ImageRevisionHold):
                    gate.inspect_pair(images=images, source_sha=sha)

    def test_workflow_build_args_and_docker_inspection_are_fail_closed(self):
        workflow = (ROOT / ".github/workflows/stage15-offline-image-bundles.yml").read_text()
        panel = (ROOT / "panel/Dockerfile").read_text()
        node = (ROOT / "node/Dockerfile").read_text()
        for dockerfile in (panel, node):
            self.assertIn("ARG SMITE_SOURCE_SHA=unverified", dockerfile)
            self.assertIn('LABEL org.opencontainers.image.revision="${SMITE_SOURCE_SHA}"',
                          dockerfile)
        self.assertGreaterEqual(
            workflow.count('--build-arg SMITE_SOURCE_SHA="$SMITE_BUILD_SOURCE_SHA"'), 2)
        self.assertIn("docker image inspect smite-panel:stage15-local smite-node:stage15-local",
                      workflow)
        self.assertIn("tests/stage15_image_revision_gate.py --inspect-json", workflow)
        self.assertIn('--expected-commit "$SMITE_BUILD_SOURCE_SHA"', workflow)
        self.assertIn("NO_GHCR_PUSH=YES", workflow)

    def test_cli_untrusted_file_and_wrong_source_hold(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            data = folder / "inspect.json"
            data.write_text(json.dumps(self.good()))
            cmd = [sys.executable, "-B", str(MODULE), "--inspect-json", str(data),
                   "--expected-commit", SOURCE]
            ok = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertIn("RELEASE_ALLOWED=NO", ok.stdout)
            fail = subprocess.run(cmd[:-1] + ["f" * 40],
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(fail.returncode, 2)
            data.unlink()
            data.symlink_to(folder / "missing")
            fail = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            self.assertEqual(fail.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
