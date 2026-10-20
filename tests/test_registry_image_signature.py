"""Non-publishing validation of digest-only keyless signing contract.

Mocks cosign only; asserts workflow wiring and negative fail-closed behavior.
Not cryptographic verification of a real GHCR image.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/sign-verified-image.sh"
PUB = ROOT / ".github/workflows/publish-images.yml"
SHA = "b" * 40
DIGEST = "sha256:" + "c" * 64


class RegistryImageSignatureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        fake = self.folder / "cosign"
        fake.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$SMITE_TEST_LOG\"\n"
            "if [ \"$1\" = verify ] && [ \"${SMITE_TEST_FAIL_VERIFY:-0}\" = 1 ]; then exit 6; fi\n"
            "if [ \"$1\" = sign ] && [ \"${SMITE_TEST_FAIL_SIGN:-0}\" = 1 ]; then exit 7; fi\n"
        )
        fake.chmod(0o700)
        self.log = self.folder / "log"
        self.env = dict(os.environ,
            PATH=str(self.folder) + os.pathsep + os.environ["PATH"],
            SMITE_TEST_LOG=str(self.log),
            GITHUB_REPOSITORY="aghajani82/Smite",
            GITHUB_REPOSITORY_OWNER="aghajani82",
            GITHUB_REF="refs/tags/v2.0.0-rc.0",
            GITHUB_SHA=SHA,
            SMITE_IMAGE_ROLE="node",
            SMITE_IMAGE_DIGEST=DIGEST)

    def check(self, **changes):
        env = dict(self.env, **changes)
        if self.log.exists():
            self.log.unlink()
        return subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True,
                              env=env, timeout=10)

    def test_exact_digest_signature_and_exact_oidc_identity(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.log.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        image = "ghcr.io/aghajani82/smite-node@" + DIGEST
        for call in calls:
            self.assertIn(image, call)
            self.assertIn("smite_source_sha=" + SHA, call)
            self.assertIn("smite_role=node", call)
        self.assertTrue(calls[0].startswith("sign --yes "))
        self.assertTrue(calls[1].startswith("verify "))
        self.assertIn("--certificate-identity=https://github.com/aghajani82/Smite/.github/workflows/publish-images.yml@refs/tags/v2.0.0-rc.0", calls[1])
        self.assertIn("--certificate-oidc-issuer=https://token.actions.githubusercontent.com", calls[1])

    def test_invalid_contexts_do_not_call_signer(self):
        invalid = [
            {"SMITE_IMAGE_ROLE": "frp"},
            {"SMITE_IMAGE_DIGEST": "sha256:" + "g" * 64},
            {"SMITE_IMAGE_DIGEST": "sha256:" + "1" * 32},
            {"SMITE_IMAGE_DIGEST": "latest"},
            {"GITHUB_SHA": "invalid"},
            {"GITHUB_REPOSITORY": "malicious/Smite"},
            {"GITHUB_REPOSITORY_OWNER": "other"},
            {"GITHUB_REF": "refs/heads/feature/malicious"},
            {"GITHUB_REF": "refs/tags/testing"},
        ]
        for change in invalid:
            with self.subTest(change=change):
                result = self.check(**change)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.log.exists(), "Unexpected cosign invocation")

    def test_failed_sign_or_verify_is_fatal(self):
        bad_sign = self.check(SMITE_TEST_FAIL_SIGN="1")
        self.assertNotEqual(bad_sign.returncode, 0)
        self.assertEqual(len(self.log.read_text().splitlines()), 1)
        bad_verify = self.check(SMITE_TEST_FAIL_VERIFY="1")
        self.assertNotEqual(bad_verify.returncode, 0)
        self.assertEqual(len(self.log.read_text().splitlines()), 2)

    def test_publisher_is_wired_but_not_executed_by_preview_ci(self):
        doc = PUB.read_text()
        self.assertNotIn("\n  pull_request:", doc)
        self.assertEqual(doc.count("sigstore/cosign-installer@v4.1.0"), 2)
        self.assertEqual(doc.count("bash scripts/sign-verified-image.sh"), 2)
        self.assertEqual(doc.count("ref: ${{ github.sha }}"), 4)  # prepare + two images + signed pair
        self.assertEqual(doc.count('test "$(git rev-parse HEAD)" = "${{ github.sha }}"'), 2)
        for role in ("panel", "node"):
            section = doc.split("  build-" + role + ":\n", 1)[1].split("\n  build-", 1)[0]
            self.assertIn("id: pushed-" + role, section)
            self.assertIn("SMITE_IMAGE_ROLE: " + role, section)
            self.assertIn("SMITE_IMAGE_DIGEST: ${{ steps.pushed-" + role + ".outputs.digest }}", section)
            self.assertIn("id-token: write", section)
            self.assertIn("SMITE_SOURCE_SHA=${{ github.sha }}", section)
        preview = (ROOT / ".github/workflows/stage15-offline-image-bundles.yml").read_text()
        self.assertIn("python -B tests/test_registry_image_signature.py -v", preview)
        self.assertIn("NO_GHCR_PUSH=YES", preview)


if __name__ == "__main__":
    unittest.main(verbosity=2)
