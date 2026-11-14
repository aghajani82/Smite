#!/usr/bin/env python3
"""Inert branch-only trial pair handoff. NOT a Smite release or install approval.

Both digests must originate from successful signed build jobs in the same
push workflow. This manifest is not itself a signature; independently verify
both Cosign signatures and the externally pinned manifest SHA256 before use.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SHA = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
BRANCH = "refs/heads/trial/unified-smite-install"
VERSION = "2.0.0-unified-install-trial"


class PairHold(ValueError):
    pass


def build_pair(*, source_sha: str, publish_ref: str, panel_digest: str,
               node_digest: str) -> dict:
    if (not isinstance(source_sha, str) or not SHA.fullmatch(source_sha)
            or publish_ref != BRANCH):
        raise PairHold("Unapproved unified trial source/ref")
    if (not isinstance(panel_digest, str) or not DIGEST.fullmatch(panel_digest)
            or not isinstance(node_digest, str) or not DIGEST.fullmatch(node_digest)
            or panel_digest == node_digest):
        raise PairHold("Two distinct immutable registry digests required")
    return {
        "schema": 1,
        "kind": "smite_unified_install_signed_trial_candidate",
        "source_repo": "aghajani82/Smite",
        "source_commit": source_sha,
        "publish_ref": BRANCH,
        "version": VERSION,
        "images": {
            "panel": "ghcr.io/aghajani82/smite-panel@" + panel_digest,
            "node": "ghcr.io/aghajani82/smite-node@" + node_digest,
        },
        "activation_allowed": False,
        "release_approved": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--publish-ref", required=True)
    parser.add_argument("--panel-digest", required=True)
    parser.add_argument("--node-digest", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        doc = build_pair(source_sha=args.source_sha, publish_ref=args.publish_ref,
                         panel_digest=args.panel_digest, node_digest=args.node_digest)
        out = args.output
        if (out.is_symlink() or not out.parent.is_dir()
                or (out.exists() and not out.is_file())):
            raise PairHold("Unsafe trial manifest destination")
        data = (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with out.open("xb") as stream:
            stream.write(data)
            stream.flush()
    except (PairHold, OSError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2
    print("UNIFIED_TRIAL_MANIFEST_SHA256=" + hashlib.sha256(data).hexdigest())
    print("HOST_ACTIVATION_AUTHORIZED=NO")
    print("MAIN_RELEASE_APPROVED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
