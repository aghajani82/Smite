"""Offline contract tests; never sign or publish a real image."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/unified-trial-sign-image.sh"
CREATE = ROOT / "scripts/create-unified-trial-pair.py"
WORKFLOW = ROOT / ".github/workflows/unified-install-signed-trial.yml"
spec = importlib.util.spec_from_file_location("unified_trial_pair", CREATE)
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)
SHA = "a" * 40
PANEL = "sha256:" + "b" * 64
NODE = "sha256:" + "c" * 64


class TrialSigning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        signer = self.dir / "cosign"
        signer.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$SMITE_TEST_LOG\"\n"
            "if [ \"$1\" = verify ] && [ \"${SMITE_TEST_FAIL_VERIFY:-0}\" = 1 ]; then exit 7; fi\n"
            "if [ \"$1\" = sign ] && [ \"${SMITE_TEST_FAIL_SIGN:-0}\" = 1 ]; then exit 6; fi\n")
        signer.chmod(0o700)
        self.log = self.dir / "signed.log"
        self.env = dict(os.environ,
            PATH=str(self.dir) + os.pathsep + os.environ["PATH"],
            SMITE_TEST_LOG=str(self.log),
            GITHUB_REPOSITORY="aghajani82/Smite",
            GITHUB_REPOSITORY_OWNER="aghajani82",
            GITHUB_REF="refs/heads/trial/unified-smite-install",
            GITHUB_EVENT_NAME="push",
            GITHUB_ACTOR="aghajani82",
            GITHUB_SHA=SHA,
            SMITE_IMAGE_ROLE="node",
            SMITE_IMAGE_DIGEST=NODE)

    def execute(self, **patch):
        if self.log.exists():
            self.log.unlink()
        return subprocess.run(["bash",str(SCRIPT)],env={**self.env,**patch},
                              capture_output=True,text=True,timeout=10)

    def test_cosign_signature_is_exact_immutable_branch_identity(self):
        output = self.execute()
        self.assertEqual(output.returncode,0,output.stderr)
        lines = self.log.read_text().splitlines()
        self.assertEqual(len(lines),2)
        image = "ghcr.io/aghajani82/smite-node@"+NODE
        for line in lines:
            self.assertIn(image,line)
            self.assertIn("smite_role=node",line)
            self.assertIn("smite_source_sha="+SHA,line)
            self.assertIn("smite_trial=unified-install",line)
        self.assertIn("sign --yes",lines[0])
        self.assertIn("--certificate-identity=https://github.com/aghajani82/Smite/.github/workflows/unified-install-signed-trial.yml@refs/heads/trial/unified-smite-install",lines[1])
        self.assertIn("--certificate-github-workflow-trigger=push",lines[1])
        self.assertIn("--certificate-github-workflow-sha="+SHA,lines[1])
        self.assertNotIn("--insecure-ignore-tlog",lines[1])
        self.assertIn("MAIN_RELEASE_APPROVED=NO",output.stdout)

    def test_invalid_context_never_invokes_signer(self):
        for invalid in (
            {"GITHUB_REF":"refs/heads/main"},
            {"GITHUB_REF":"refs/tags/v2.0.0-rc.7"},
            {"GITHUB_EVENT_NAME":"pull_request"},
            {"GITHUB_EVENT_NAME":"workflow_dispatch"},
            {"GITHUB_ACTOR":"fork-user"},
            {"GITHUB_REPOSITORY":"evil/Smite"},
            {"GITHUB_REPOSITORY_OWNER":"elsewhere"},
            {"GITHUB_SHA":"not-a-source-sha"},
            {"SMITE_IMAGE_ROLE":"frp"},
            {"SMITE_IMAGE_DIGEST":"latest"},
            {"SMITE_IMAGE_DIGEST":"sha256:"+"z"*64},
        ):
            with self.subTest(invalid=invalid):
                self.assertNotEqual(self.execute(**invalid).returncode,0)
                self.assertFalse(self.log.exists())

    def test_sign_or_verify_error_fatal(self):
        self.assertNotEqual(self.execute(SMITE_TEST_FAIL_SIGN="1").returncode,0)
        self.assertEqual(len(self.log.read_text().splitlines()),1)
        self.assertNotEqual(self.execute(SMITE_TEST_FAIL_VERIFY="1").returncode,0)
        self.assertEqual(len(self.log.read_text().splitlines()),2)

    def test_manifest_contract_and_exact_scope(self):
        result=pair.build_pair(source_sha=SHA,publish_ref=pair.BRANCH,
                               panel_digest=PANEL,node_digest=NODE)
        self.assertEqual(result["source_commit"],SHA)
        self.assertEqual(result["images"]["panel"],"ghcr.io/aghajani82/smite-panel@"+PANEL)
        self.assertEqual(result["images"]["node"],"ghcr.io/aghajani82/smite-node@"+NODE)
        self.assertIs(result["activation_allowed"],False)
        self.assertIs(result["release_approved"],False)
        self.assertEqual(result["kind"],"smite_unified_install_signed_trial_candidate")
        for changed in (
            {"publish_ref":"refs/heads/main"},
            {"publish_ref":"refs/tags/v2.0.0-rc.7"},
            {"source_sha":"bad"},
            {"node_digest":PANEL},
            {"panel_digest":"sha256:"+"z"*64},
        ):
            with self.subTest(changed=changed), self.assertRaises(pair.PairHold):
                pair.build_pair(**{**dict(source_sha=SHA,publish_ref=pair.BRANCH,
                    panel_digest=PANEL,node_digest=NODE),**changed})

    def test_manifest_cli_no_overwrite_and_no_activation(self):
        out=self.dir/"pair.json"
        cmd=[sys.executable,"-B",str(CREATE),
             "--source-sha",SHA,"--publish-ref",pair.BRANCH,
             "--panel-digest",PANEL,"--node-digest",NODE,"--output",str(out)]
        one=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        self.assertEqual(one.returncode,0,one.stderr)
        self.assertEqual(json.loads(out.read_text())["version"],pair.VERSION)
        two=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        self.assertNotEqual(two.returncode,0)
        self.assertIn("MAIN_RELEASE_APPROVED=NO",one.stdout)

    def test_workflow_is_branch_only_and_never_publishes_mutable_tags(self):
        yml=WORKFLOW.read_text()
        self.assertIn("trial/unified-smite-install",yml)
        self.assertIn("github.actor == 'aghajani82'",yml)
        self.assertIn("github.event_name == 'push'",yml)
        self.assertIn("needs: [preflight, build-panel, build-node]",yml)
        self.assertIn("scripts/unified-trial-sign-image.sh",yml)
        self.assertIn("scripts/create-unified-trial-pair.py",yml)
        self.assertEqual(yml.count("push-by-digest=true,name-canonical=true,push=true"),2)
        self.assertEqual(yml.count("SMITE_SOURCE_SHA="),2)
        self.assertEqual(yml.count("sigstore/cosign-installer@v4.1.0"),2)
        self.assertNotIn("refs/heads/main",yml)
        self.assertNotIn("workflow_dispatch:",yml)
        self.assertNotIn("tags: latest",yml)
        self.assertNotIn("docker/metadata-action",yml)
        self.assertNotIn("docker compose up",yml)
        self.assertIn("NO_DEPLOYMENT_OR_RELEASE=YES",yml)


if __name__=="__main__":
    unittest.main(verbosity=2)
