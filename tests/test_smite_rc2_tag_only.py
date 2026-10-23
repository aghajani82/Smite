#!/usr/bin/env python3
"""No-side-effect checks for owner-approved RC2 tag-only workflow."""
from pathlib import Path
import os
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/smite-rc2-tag-only.yml"
TAG = "v2.0.0-rc.2"
SOURCE_SHA = "e6c3ecce81010130ae28e7d1e37ea99b31d70c28"
REVIEWED_SHA = "31543e2e81ea635b4eaab87f606125b4e4dd22e1"


class CandidateTagOnlyTests(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("        run: |\n", self.source)
        self.script = textwrap.dedent(
            self.source.split("        run: |\n", 1)[1]
        )

    def test_workflow_keeps_release_and_registry_separate(self):
        self.assertIn("  pull_request:\n", self.source)
        self.assertIn("  workflow_dispatch:\n", self.source)
        self.assertIn("  contents: read\n", self.source)
        self.assertIn("    if: github.event_name == 'workflow_dispatch'", self.source)
        self.assertIn("    needs: offline-gate\n", self.source)
        self.assertIn("      contents: write\n", self.source)
        self.assertIn("confirm_tag_only:", self.source)
        self.assertIn("expected_source_sha:", self.source)
        self.assertIn("persist-credentials: true", self.source)
        self.assertNotIn("docker/login-action", self.source)
        self.assertNotIn("docker/build-push-action", self.source)
        self.assertNotIn("gh release", self.source)
        self.assertNotIn("force-push", self.source)
        self.assertNotIn("git push --force", self.source)
        self.assertNotIn("create-release", self.source)

    def test_exact_source_and_signoff_guard_precedes_write(self):
        self.assertIn(f'tag="{TAG}"', self.script)
        self.assertIn(f'reviewed="{SOURCE_SHA}"', self.script)
        self.assertIn(f'pr_head="{REVIEWED_SHA}"', self.script)
        for marker in (
            '[[ "$GITHUB_EVENT_NAME" == "workflow_dispatch" ]] || hold',
            '[[ "$GITHUB_REPOSITORY" == "aghajani82/Smite" ]] || hold',
            '[[ "$GITHUB_ACTOR" == "aghajani82" ]] || hold',
            '[[ "$GITHUB_REF" == "refs/heads/main" ]] || hold',
            '[[ "$CONFIRM_TAG_ONLY" == "true" ]] || hold',
            '[[ "$EXPECTED_SOURCE_SHA" == "$reviewed" ]] || hold',
            "git merge-base --is-ancestor",
            "git diff --quiet",
            "git ls-remote --tags origin",
            'git push origin "refs/tags/$tag:refs/tags/$tag" || hold',
        ):
            self.assertIn(marker, self.script)
        self.assertLess(
            self.script.index('[[ "$CONFIRM_TAG_ONLY"'),
            self.script.index("git config user.name"),
        )
        self.assertLess(
            self.script.index("git diff --quiet"),
            self.script.index("git tag -a"),
        )
        self.assertLess(
            self.script.index("git ls-remote --tags origin"),
            self.script.index("git push origin"),
        )
        syntax = subprocess.run(
            ["bash", "-n"], input=self.script, capture_output=True, text=True
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_bad_owner_ref_source_and_consent_fail_before_git(self):
        context = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "aghajani82/Smite",
            "GITHUB_ACTOR": "aghajani82",
            "GITHUB_REF": "refs/heads/main",
            "CONFIRM_TAG_ONLY": "true",
            "EXPECTED_SOURCE_SHA": SOURCE_SHA,
        }
        bad = (
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_REPOSITORY": "attacker/repo"},
            {"GITHUB_ACTOR": "unknown"},
            {"GITHUB_REF": "refs/tags/v2.0.0-rc.1"},
            {"CONFIRM_TAG_ONLY": "false"},
            {"EXPECTED_SOURCE_SHA": "0" * 40},
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fakebin = root / "bin"
            fakebin.mkdir()
            audit = root / "git-called"
            git = fakebin / "git"
            git.write_text(
                '#!/bin/sh\nprintf "called\\n" >> "$GIT_AUDIT"\nexit 1\n',
                encoding="utf-8",
            )
            git.chmod(0o700)
            for change in bad:
                with self.subTest(change=change):
                    audit.unlink(missing_ok=True)
                    env = {
                        **os.environ, **context, **change,
                        "GIT_AUDIT": str(audit),
                        "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
                    }
                    p = subprocess.run(
                        ["bash", "-c", self.script],
                        env=env, capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(p.returncode, 2, p.stderr)
                    self.assertIn("HOLD:", p.stderr)
                    self.assertFalse(audit.exists(), "Git must not be called")


if __name__ == "__main__":
    unittest.main()
