#!/usr/bin/env python3
"""Stage15: build/verify an UNPUBLISHED two-image offline Docker archive bundle.

Creates a manifest with SHA256 hashes of Docker-save gzip archives,
immutable local image IDs, and an exact reviewed Git source commit.
This does NOT produce trusted OCI registry digests, attest signatures,
prove runtime mounts/TLS/UIDs, or permit server deployment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
FILES = ("smite-panel-stage15.docker.tar.gz", "smite-node-stage15.docker.tar.gz")


class BundleInvalid(ValueError):
    pass


def digest_file(path: Path) -> tuple[str, int]:
    if not path.is_file() or path.is_symlink():
        raise BundleInvalid("Missing or unsafe bundle archive")
    sha = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            sha.update(block)
            size += len(block)
    if size <= 0:
        raise BundleInvalid("Empty image archive")
    return sha.hexdigest(), size


def create(*, source_sha: str, panel_id: str, node_id: str, folder: Path) -> dict:
    if not SHA40.fullmatch(source_sha):
        raise BundleInvalid("Invalid pinned Git source SHA")
    for image_id in (panel_id, node_id):
        if not ID.fullmatch(image_id):
            raise BundleInvalid("Invalid local image ID")
    if panel_id == node_id:
        raise BundleInvalid("Panel and Node image IDs must be distinct")
    if folder.is_symlink() or not folder.is_dir():
        raise BundleInvalid("Invalid bundle directory")
    files = {}
    for role, archive in zip(("panel", "node"), FILES):
        sha, size = digest_file(folder / archive)
        files[role] = {
            "file": archive,
            "archive_sha256": sha,
            "bytes": size,
            "local_image_id": panel_id if role == "panel" else node_id,
        }
    return {
        "schema": 1,
        "kind": "smite_offline_preview_images",
        "source_repo": "aghajani82/Smite",
        "source_commit": source_sha,
        "proposed_version": "2.0.0-rc.0",
        "image_format": "docker-save-gzip",
        "images": files,
        "signed": False,
        "registry_digest_verified": False,
        "runtime_security_verified": False,
        "activation_allowed": False,
    }


def verify(manifest_path: Path, *, expected_commit: str | None = None) -> dict:
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise BundleInvalid("Manifest missing or untrusted")
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (OSError, ValueError, UnicodeError) as exc:
        raise BundleInvalid("Invalid manifest") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise BundleInvalid("Unknown manifest format")
    if manifest.get("kind") != "smite_offline_preview_images":
        raise BundleInvalid("Wrong bundle type")
    if manifest.get("source_repo") != "aghajani82/Smite" or not SHA40.fullmatch(
        str(manifest.get("source_commit"))
    ):
        raise BundleInvalid("Untrusted source declaration")
    if expected_commit is not None and manifest["source_commit"] != expected_commit:
        raise BundleInvalid("Unexpected source revision")
    if (
        manifest.get("proposed_version") != "2.0.0-rc.0"
        or manifest.get("image_format") != "docker-save-gzip"
        or manifest.get("signed") is not False
        or manifest.get("registry_digest_verified") is not False
        or manifest.get("runtime_security_verified") is not False
        or manifest.get("activation_allowed") is not False
    ):
        raise BundleInvalid("Preview bundle must remain non-deployable")
    images = manifest.get("images")
    if not isinstance(images, dict) or set(images) != {"panel", "node"}:
        raise BundleInvalid("Bundle must contain exactly Panel and Node")
    seen_ids = set()
    for role, name in zip(("panel", "node"), FILES):
        item = images[role]
        if not isinstance(item, dict) or item.get("file") != name:
            raise BundleInvalid("Wrong archive name")
        if (
            not SHA64.fullmatch(str(item.get("archive_sha256")))
            or not isinstance(item.get("bytes"), int) or item["bytes"] <= 0
            or not ID.fullmatch(str(item.get("local_image_id")))
        ):
            raise BundleInvalid("Invalid file checksum/size/image ID")
        seen_ids.add(item["local_image_id"])
        actual, size = digest_file(manifest_path.parent / name)
        if actual != item["archive_sha256"] or size != item["bytes"]:
            raise BundleInvalid("Archive changed or checksum mismatch")
    if len(seen_ids) != 2:
        raise BundleInvalid("Duplicate image IDs")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("create")
    p.add_argument("--folder", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--panel-image-id", required=True)
    p.add_argument("--node-image-id", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--manifest", type=Path, required=True)
    v.add_argument("--expected-commit")
    args = parser.parse_args()
    try:
        if args.mode == "create":
            bundle = create(
                source_sha=args.source_sha, panel_id=args.panel_image_id,
                node_id=args.node_image_id, folder=args.folder,
            )
            manifest = args.folder / "stage15-images.json"
            if manifest.exists() or manifest.is_symlink():
                raise BundleInvalid("Refusing to replace existing manifest")
            with manifest.open("x", encoding="utf-8") as stream:
                json.dump(bundle, stream, sort_keys=True, indent=2)
                stream.write("\n")
            verify(manifest, expected_commit=args.source_sha)
        else:
            verify(args.manifest, expected_commit=args.expected_commit)
        print("OFFLINE_PREVIEW_ARCHIVES=CHECKSUM_VERIFIED")
        print("IMAGE_REGISTRY_PROVENANCE=UNVERIFIED")
        print("LIVE_DEPLOYMENT=BLOCKED")
        return 0
    except (BundleInvalid, OSError, TypeError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
