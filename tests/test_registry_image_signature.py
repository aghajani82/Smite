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
            GITHUB_EVENT_NAME="workflow_dispatch",
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
            {"GITHUB_REF": "refs/heads/main"},
            {"GITHUB_REF": "refs/heads/next"},
            {"GITHUB_REF": "refs/tags/v2.0.0-rc.0", "GITHUB_EVENT_NAME": "push"},
            {"GITHUB_REF": "refs/tags/v2.0.0-rc.0", "GITHUB_EVENT_NAME": "workflow_dispatch-fake"},
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

    def test_manual_approval_gate_executes_against_real_disposable_git_tag(self):
        # Exercise the workflow bash gate itself, not only static YAML words.
        source = PUB.read_text()
        block = source.split("      - name: Reject all unapproved or mismatched release candidates\n", 1)[1]
        block = block.split("\n  build-panel:\n", 1)[0]
        script = block.split("        run: |\n", 1)[1]
        script = "\n".join(line[10:] for line in script.splitlines()
                           if line.strip()) + "\n"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            subprocess.run(["git", "init", "-q", str(root)], check=True,
                           capture_output=True, text=True, timeout=10)
            commit = subprocess.run(
                ["git", "-c", "user.name=review", "-c", "user.email=review@example.invalid",
                 "commit", "--allow-empty", "-qm", "synthetic reviewed candidate"],
                cwd=root, capture_output=True, text=True, timeout=10)
            self.assertEqual(commit.returncode, 0, commit.stderr)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                          cwd=root, text=True).strip()
            subprocess.run(["git", "tag", "v2.0.0-rc.0"], cwd=root, check=True,
                           capture_output=True, text=True, timeout=10)
            output = root / "approved-output.txt"
            env = dict(os.environ,
                       GITHUB_EVENT_NAME="workflow_dispatch",
                       GITHUB_REPOSITORY="aghajani82/Smite",
                       GITHUB_ACTOR="aghajani82",
                       GITHUB_REF_TYPE="tag",
                       GITHUB_REF="refs/tags/v2.0.0-rc.0",
                       GITHUB_SHA=sha,
                       EXPECTED_TAG="v2.0.0-rc.0",
                       EXPECTED_SHA=sha,
                       APPROVED="true",
                       GITHUB_OUTPUT=str(output))
            def invoke(**override):
                if output.exists():
                    output.unlink()
                result = subprocess.run(["bash", "-c", script], cwd=root,
                                        capture_output=True, text=True,
                                        env=dict(env, **override), timeout=10)
                return result, output.read_text() if output.exists() else ""
            accepted, approved_output = invoke()
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn("result=true", approved_output)
            self.assertIn("version=2.0.0-rc.0", approved_output)
            self.assertIn("RELEASE_AND_DEPLOYMENT_APPROVED=NO", accepted.stdout)
            for override in (
                {"APPROVED": "false"}, {"EXPECTED_SHA": "0" * 40},
                {"EXPECTED_TAG": "v2.0.1"}, {"GITHUB_REF_TYPE": "branch"},
                {"GITHUB_REF": "refs/heads/main"},
                {"GITHUB_EVENT_NAME": "push"},
                {"GITHUB_REPOSITORY": "attacker/Smite"},
                {"GITHUB_ACTOR": "unauthorized-contributor"},
            ):
                with self.subTest(override=override):
                    denied, attempted_output = invoke(**override)
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertEqual(attempted_output, "")

    def test_publisher_refuses_automatic_push_or_mutable_aliases(self):
        workflow = PUB.read_text()
        self.assertIn("\n  workflow_dispatch:\n", workflow)
        self.assertNotIn("\n  push:\n", workflow)
        for field in ("expected_release_tag", "expected_source_sha",
                      "confirm_candidate_publication"):
            self.assertIn(field, workflow)
        self.assertIn('[[ "$APPROVED" == "true" ]] || hold', workflow)
        self.assertIn('[[ "$GITHUB_REF_TYPE" == "tag" ]] || hold', workflow)
        self.assertIn('[[ "$GITHUB_ACTOR" == "aghajani82" ]] || hold', workflow)
        self.assertIn('[[ "$GITHUB_REF" == "refs/tags/$EXPECTED_TAG" ]] || hold', workflow)
        self.assertIn('[[ "$GITHUB_SHA" == "$EXPECTED_SHA" ]] || hold', workflow)
        self.assertIn('[[ "$(git rev-parse HEAD)" == "$EXPECTED_SHA" ]] || hold', workflow)
        self.assertIn('[[ "$(git rev-parse "${GITHUB_REF}^{commit}")" == "$EXPECTED_SHA" ]] || hold', workflow)
        self.assertEqual(workflow.count("type=raw,value=${{ needs.prepare.outputs.version }}"), 2)
        for forbidden in ("type=ref,event=branch", "type=ref,event=pr",
                          "type=semver", "type=sha", "type=raw,value=latest",
                          "type=raw,value=tst", "dorny/paths-filter@"):
            self.assertNotIn(forbidden, workflow)
        self.assertIn("RELEASE_AND_DEPLOYMENT_APPROVED=NO", workflow)

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
