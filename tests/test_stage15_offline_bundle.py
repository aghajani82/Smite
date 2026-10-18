"""Stage15 checksums verify a pair of offline archives, not production trust."""
import json
from pathlib import Path
import tempfile
import unittest

from stage15_offline_bundle import BundleInvalid, create, verify


COMMIT = "a" * 40
PANEL_ID = "sha256:" + "b" * 64
NODE_ID = "sha256:" + "c" * 64


class PreviewBundleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        (self.folder / "smite-panel-stage15.docker.tar.gz").write_bytes(b"tiny-unit-test-panel")
        (self.folder / "smite-node-stage15.docker.tar.gz").write_bytes(b"tiny-unit-test-node")
        self.manifest = self.folder / "stage15-images.json"

    def make(self):
        obj = create(
            source_sha=COMMIT, panel_id=PANEL_ID, node_id=NODE_ID,
            folder=self.folder,
        )
        self.manifest.write_text(json.dumps(obj))
        return obj

    def test_checksum_and_source_pin_but_no_authorization(self):
        doc = self.make()
        result = verify(self.manifest, expected_commit=COMMIT)
        self.assertEqual(doc, result)
        self.assertFalse(result["activation_allowed"])
        self.assertFalse(result["signed"])
        self.assertFalse(result["registry_digest_verified"])
        self.assertFalse(result["runtime_security_verified"])
        self.assertNotIn("docker run", self.manifest.read_text())

    def test_corrupted_archive_fails(self):
        self.make()
        (self.folder / "smite-node-stage15.docker.tar.gz").write_bytes(b"tampered")
        with self.assertRaises(BundleInvalid):
            verify(self.manifest, expected_commit=COMMIT)

    def test_mismatched_commit_fails(self):
        self.make()
        with self.assertRaises(BundleInvalid):
            verify(self.manifest, expected_commit="f" * 40)

    def test_extra_role_wrong_archive_and_deploy_flag_fail(self):
        manifest = self.make()
        manifest["images"]["attacker"] = manifest["images"]["panel"]
        self.manifest.write_text(json.dumps(manifest))
        with self.assertRaises(BundleInvalid):
            verify(self.manifest)
        manifest["images"].pop("attacker")
        manifest["images"]["panel"]["file"] = "../out.tar.gz"
        self.manifest.write_text(json.dumps(manifest))
        with self.assertRaises(BundleInvalid):
            verify(self.manifest)
        manifest["images"]["panel"]["file"] = "smite-panel-stage15.docker.tar.gz"
        manifest["activation_allowed"] = True
        self.manifest.write_text(json.dumps(manifest))
        with self.assertRaises(BundleInvalid):
            verify(self.manifest)

    def test_duplicate_image_id_and_symlink_fail(self):
        doc = self.make()
        doc["images"]["node"]["local_image_id"] = PANEL_ID
        self.manifest.write_text(json.dumps(doc))
        with self.assertRaises(BundleInvalid):
            verify(self.manifest)
        self.manifest.unlink()
        self.manifest.symlink_to(self.folder / "smite-panel-stage15.docker.tar.gz")
        with self.assertRaises(BundleInvalid):
            verify(self.manifest)

    def test_create_rejects_empty_archives(self):
        (self.folder / "smite-node-stage15.docker.tar.gz").write_bytes(b"")
        with self.assertRaises(BundleInvalid):
            create(source_sha=COMMIT, panel_id=PANEL_ID,
                   node_id=NODE_ID, folder=self.folder)


if __name__ == "__main__":
    unittest.main()
