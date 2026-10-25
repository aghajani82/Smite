#!/usr/bin/env python3
"""Offline admission for RC4 lab-only immutable tag workflow.

No GitHub writes, no network access, no container or server changes.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/smite-rc2-tag-only.yml"
LAB_TAG = "v2.0.0-rc.4"
BRANCH = "refs/heads/feature/smite-rc2-frp-singleton-multiport-20261025"


class LabRc4TagOnlyTest(unittest.TestCase):
    def setUp(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(content.count("  lab-tag-only:\n"), 1)
        self.workflow, self.lab = content.split("  lab-tag-only:\n", 1)
        self.assertEqual(self.lab.count("        run: |\n"), 1)
        self.script = textwrap.dedent(self.lab.split("        run: |\n", 1)[1])

    def test_tag_workflow_separate_from_release_and_server_operations(self):
        self.assertIn(f'tag="{LAB_TAG}"', self.script)
        self.assertIn(f'required_branch="{BRANCH}"', self.script)
        self.assertNotIn("docker/login-action", self.lab)
        self.assertNotIn("docker/build-push-action", self.lab)
        self.assertNotIn("gh release", self.lab)
        self.assertNotIn("docker compose", self.lab)
        self.assertNotIn("git push --force", self.script)
        self.assertIn("GHCR_PUSH=NO", self.script)
        self.assertIn("MAIN_MERGE=NO", self.script)
        self.assertIn("DEPLOYMENT=NO", self.script)
        self.assertIn('git tag -a "$tag" "$EXPECTED_SOURCE_SHA"', self.script)

    def test_exact_actor_branch_commit_and_consent_precede_git_push(self):
        for expected in (
            '[[ "$GITHUB_EVENT_NAME" == "workflow_dispatch" ]] || hold',
            '[[ "$GITHUB_REPOSITORY" == "aghajani82/Smite" ]] || hold',
            '[[ "$GITHUB_ACTOR" == "aghajani82" ]] || hold',
            '[[ "$GITHUB_REF" == "$required_branch" ]] || hold',
            '[[ "$CONFIRM_TAG_ONLY" == "true" ]] || hold',
            '[[ "$EXPECTED_SOURCE_SHA" =~ ^[a-f0-9]{40}$ ]] || hold',
            '[[ "$EXPECTED_SOURCE_SHA" == "$GITHUB_SHA" ]] || hold',
            '[[ "$(git rev-parse HEAD)" == "$EXPECTED_SOURCE_SHA" ]] || hold',
            'git merge-base --is-ancestor "$original_rc3" HEAD || hold',
            'git merge-base --is-ancestor "$required_fix" HEAD || hold',
            'git merge-base --is-ancestor "$reviewed_merge" HEAD || hold',
            'git ls-remote --heads origin',
            'git ls-remote --tags origin',
            'git push origin "refs/tags/$tag:refs/tags/$tag" || hold',
        ):
            self.assertIn(expected, self.script)
        self.assertLess(self.script.index('"$CONFIRM_TAG_ONLY"'), self.script.index("git config user.name"))
        self.assertLess(self.script.index("git ls-remote --tags origin"), self.script.index("git tag -a"))
        result = subprocess.run(["bash", "-n"], input=self.script, text=True,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_release_context_stops_before_git_or_side_effects(self):
        valid = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "aghajani82/Smite",
            "GITHUB_ACTOR": "aghajani82",
            "GITHUB_REF": BRANCH,
            "CONFIRM_TAG_ONLY": "true",
            "GITHUB_SHA": "b" * 40,
            "EXPECTED_SOURCE_SHA": "b" * 40,
        }
        negative_cases = [
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_REPOSITORY": "other/repository"},
            {"GITHUB_ACTOR": "other"},
            {"GITHUB_REF": "refs/heads/main"},
            {"CONFIRM_TAG_ONLY": "false"},
            {"GITHUB_SHA": "c" * 40},
            {"EXPECTED_SOURCE_SHA": "not-a-sha"},
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fakebin = root / "bin"
            fakebin.mkdir()
            audit = root / "git-called"
            stub = fakebin / "git"
            stub.write_text('#!/bin/sh\nprintf "called\\n" >> "$GIT_AUDIT"\nexit 1\n',
                            encoding="utf-8")
            stub.chmod(0o700)
            for update in negative_cases:
                with self.subTest(update=update):
                    audit.unlink(missing_ok=True)
                    env = {
                        **os.environ, **valid, **update,
                        "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
                        "GIT_AUDIT": str(audit)
                    }
                    p = subprocess.run(["bash", "-c", self.script], env=env,
                                       text=True, capture_output=True, timeout=10)
                    self.assertEqual(p.returncode, 2, p.stderr)
                    self.assertIn("HOLD:", p.stderr)
                    self.assertFalse(audit.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
