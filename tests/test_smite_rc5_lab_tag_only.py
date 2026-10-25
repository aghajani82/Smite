#!/usr/bin/env python3
"""Offline admission for the RC5 immutable candidate tag workflow.

No GitHub writes, network access, container operations, or server changes.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/smite-rc2-tag-only.yml"
TAG = "v2.0.0-rc.5"
SOURCE = "be00b20d64051f5bbd5597701ebdbe60b33b481c"
BRANCH = "refs/heads/feature/smite-rc5-release-gate"


class Rc5TagOnlyTest(unittest.TestCase):
    def setUp(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(content.count("  rc5-tag-only:\n"), 1)
        self.job = content.split("  rc5-tag-only:\n", 1)[1]
        self.assertEqual(self.job.count("        run: |\n"), 1)
        self.script = textwrap.dedent(self.job.split("        run: |\n", 1)[1])

    def test_offline_gate_is_wired_to_rc5_contract(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("tests/test_smite_rc5_lab_tag_only.py -v", content)
        self.assertIn("'tests/test_smite_rc5_lab_tag_only.py'", content)
        self.assertIn(f'tag="{TAG}"', self.script)
        self.assertIn(f'reviewed_source="{SOURCE}"', self.script)
        self.assertIn(f'required_branch="{BRANCH}"', self.script)

    def test_gate_is_owner_approved_exact_and_immutable(self):
        for expected in (
            '[[ "$GITHUB_EVENT_NAME" == "workflow_dispatch" ]] || hold',
            '[[ "$GITHUB_REPOSITORY" == "aghajani82/Smite" ]] || hold',
            '[[ "$GITHUB_ACTOR" == "aghajani82" ]] || hold',
            '[[ "$GITHUB_REF" == "$required_branch" ]] || hold',
            '[[ "$CONFIRM_TAG_ONLY" == "true" ]] || hold',
            '[[ "$EXPECTED_SOURCE_SHA" == "$reviewed_source" ]] || hold',
            '[[ "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]] || hold',
            '[[ "$(git rev-parse "$reviewed_source^{commit}")" == "$reviewed_source" ]] || hold',
            'git merge-base --is-ancestor "$reviewed_source" HEAD || hold',
            'git ls-remote --heads origin',
            'git ls-remote --tags origin',
            'git push origin "refs/tags/$tag:refs/tags/$tag" || hold',
            '[[ "$(awk -v ref="refs/tags/$tag^{}"',
        ):
            self.assertIn(expected, self.script)
        for forbidden in ("git push --force", "docker/", "gh release", "docker compose", "ssh "):
            self.assertNotIn(forbidden, self.job)
        self.assertIn("GHCR_PUSH=NO", self.script)
        self.assertIn("MAIN_MERGE=NO", self.script)
        self.assertIn("DEPLOYMENT=NO", self.script)
        self.assertLess(self.script.index('"$CONFIRM_TAG_ONLY"'), self.script.index("git config user.name"))
        self.assertLess(self.script.index("git ls-remote --tags origin"), self.script.index("git tag -a"))
        result = subprocess.run(["bash", "-n"], input=self.script, text=True,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_context_holds_before_any_git_operation(self):
        valid = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "aghajani82/Smite",
            "GITHUB_ACTOR": "aghajani82",
            "GITHUB_REF": BRANCH,
            "CONFIRM_TAG_ONLY": "true",
            "EXPECTED_SOURCE_SHA": SOURCE,
            "GITHUB_SHA": "b" * 40,
        }
        negative_cases = [
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_REPOSITORY": "other/repository"},
            {"GITHUB_ACTOR": "other"},
            {"GITHUB_REF": "refs/heads/main"},
            {"CONFIRM_TAG_ONLY": "false"},
            {"EXPECTED_SOURCE_SHA": "c" * 40},
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fakebin = root / "bin"
            fakebin.mkdir()
            audit = root / "git-called"
            stub = fakebin / "git"
            stub.write_text('#!/bin/sh\\nprintf "called\\n" >> "$GIT_AUDIT"\\nexit 1\\n',
                            encoding="utf-8")
            stub.chmod(0o700)
            for update in negative_cases:
                with self.subTest(update=update):
                    audit.unlink(missing_ok=True)
                    env = {
                        **os.environ, **valid, **update,
                        "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
                        "GIT_AUDIT": str(audit),
                    }
                    p = subprocess.run(["bash", "-c", self.script], env=env,
                                       text=True, capture_output=True, timeout=10)
                    self.assertEqual(p.returncode, 2, p.stderr)
                    self.assertIn("HOLD:", p.stderr)
                    self.assertFalse(audit.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
