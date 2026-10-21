#!/usr/bin/env python3
"""Strict same-source provenance gate for UNPUBLISHED Panel + Node images.

Consumes docker image inspect JSON from a trusted exact-SHA CI checkout.
Image labels are self-declarations, NOT registry signatures/attestations.
No Docker calls, network, host changes, service activation, or publishing.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

SHA40 = re.compile(r"[a-f0-9]{40}\Z")
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
REVISION_LABEL = "org.opencontainers.image.revision"
VERSION_LABEL = "org.opencontainers.image.version"


class ImageRevisionHold(ValueError):
    pass


def inspect_pair(*, images: object, source_sha: str) -> tuple[str, str]:
    if not isinstance(source_sha, str) or not SHA40.fullmatch(source_sha):
        raise ImageRevisionHold("Invalid expected reviewed source SHA")
    if not isinstance(images, list) or len(images) != 2:
        raise ImageRevisionHold("Exactly two ordered Panel and Node images required")
    result = []
    for role, image in zip(("panel", "node"), images):
        if not isinstance(image, dict):
            raise ImageRevisionHold("Invalid image inspect record")
        image_id = image.get("Id")
        config = image.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if (not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id)
                or not isinstance(labels, dict)
                or labels.get("smite.role") != role
                or labels.get(REVISION_LABEL) != source_sha
                or labels.get(VERSION_LABEL) != "2.0.0-rc.0"):
            raise ImageRevisionHold(f"{role} image revision/version/ID mismatch")
        result.append(image_id)
    if result[0] == result[1]:
        raise ImageRevisionHold("Panel and Node cannot share image ID")
    return result[0], result[1]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inspect-json", type=Path, required=True)
    p.add_argument("--expected-commit", required=True)
    args = p.parse_args(argv)
    try:
        if not args.inspect_json.is_file() or args.inspect_json.is_symlink():
            raise ImageRevisionHold("Untrusted image inspect input")
        if args.inspect_json.stat().st_size > 32768:
            raise ImageRevisionHold("Image inspect JSON too large")
        inspected = json.loads(args.inspect_json.read_bytes())
        panel_id, node_id = inspect_pair(images=inspected, source_sha=args.expected_commit)
    except (ImageRevisionHold, OSError, ValueError, TypeError, UnicodeError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2
    print("PANEL_AND_NODE_IMAGE_REVISION=EXACT_SOURCE_SHA")
    print("PANEL_NODE_IMAGE_IDS_DISTINCT=YES")
    print("OFFLINE_PREVIEW_ONLY=YES")
    print("REGISTRY_ATTESTATION=NOT_VERIFIED")
    print("RELEASE_ALLOWED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
