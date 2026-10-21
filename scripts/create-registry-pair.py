#!/usr/bin/env python3
"""Emit ONLY an inert digest-pair handoff after BOTH signed publisher jobs pass.

This is a JSON index, not a signature/attestation or install approval.
Consumers must independently pin manifest SHA256 and run their own Cosign
verification on BOTH immutable digests before even considering rollout.
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
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9][a-zA-Z0-9.-]*)?\Z")

class PairHold(ValueError):
    pass

def build_pair(*, source_sha: str, publish_ref: str, version: str,
               panel_digest: str, node_digest: str) -> dict:
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        raise PairHold("Invalid immutable Smite source")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise PairHold("Invalid release version")
    if publish_ref != "refs/tags/v" + version:
        raise PairHold("A reviewed matching version tag is required")
    if (not isinstance(panel_digest, str) or not DIGEST.fullmatch(panel_digest)
            or not isinstance(node_digest, str) or not DIGEST.fullmatch(node_digest)
            or panel_digest == node_digest):
        raise PairHold("Require two distinct real registry digests")
    return {
        "schema": 1,
        "kind": "smite_signed_registry_pair_candidate",
        "source_repo": "aghajani82/Smite",
        "source_commit": source_sha,
        "publish_ref": publish_ref,
        "version": version,
        "images": {
            "panel": "ghcr.io/aghajani82/smite-panel@" + panel_digest,
            "node": "ghcr.io/aghajani82/smite-node@" + node_digest,
        },
        "activation_allowed": False,
        "release_approved": False,
    }

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ("source-sha", "publish-ref", "version", "panel-digest", "node-digest"):
        p.add_argument("--" + flag, required=True)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        manifest = build_pair(source_sha=args.source_sha, publish_ref=args.publish_ref,
                              version=args.version, panel_digest=args.panel_digest,
                              node_digest=args.node_digest)
        if args.output.is_symlink() or not args.output.parent.is_dir():
            raise PairHold("Unsafe manifest output")
        data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with args.output.open("xb") as out:
            out.write(data)
    except (PairHold, OSError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2
    print("SMITE_PAIR_MANIFEST_SHA256=" + hashlib.sha256(data).hexdigest())
    print("SIGNED_IMAGE_JOB_DEPENDENCY=REQUIRED_BUT_NOT_INDEPENDENTLY_ATTESTED")
    print("ACTIVATION_ALLOWED=NO")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
