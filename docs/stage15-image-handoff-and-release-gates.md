# Stage 15 — Unpublished, source-locked two-image Docker test bundle

**This is the first paired binary handoff, NOT a release or a deployable
security image.** Proposed label: `2.0.0-rc.0`; no tag or GHCR push.

The workflow `.github/workflows/stage15-offline-image-bundles.yml`
builds both Panel and Node from **the exact same GitHub Commit**.
It smoke-checks the required security source files *inside* each image
without starting Smite. It then creates:

- `smite-panel-stage15.docker.tar.gz` — a `docker save` archive
- `smite-node-stage15.docker.tar.gz` — matching source version
- `stage15-images.json` — source SHA, local Docker image IDs,
  archive SHA-256 and byte lengths, proposed version and explicit
  `activation_allowed=false`

GitHub Actions uploads all three as one disposable **3-day retention**
workflow artifact. The build log prints the SHA256 of the JSON manifest
so the receiver can compare it with the downloaded bundle independently.

`tests/stage15_offline_bundle.py` creates/verifies the manifest and
`tests/test_stage15_offline_bundle.py` exercises corruption, checksum
mismatch, duplicate Panel/Node IDs, untrusted paths, wrong Commit and
accidental `activation_allowed=true`. No keys or credentials are in
the bundle manifest.

**Important security boundaries:**

1. The archive SHA verifies local bytes against the manifest. It does
   NOT independently attest who built the archive; trust still
   depends on the GitHub Actions run and a trusted manifest digest.
2. The local Docker image ID is *not* an immutable OCI registry
   manifest digest. No GHCR artifact has been signed, published or
   pinned for U-OPTI to pull. Dockerfile dependencies and binary
   downloads also need reproducibility/provenance review.
3. `docker load` of these unreviewed images is NOT performed on IR or
   KH. Future acceptance must verify actual image/container IDs and
   bind mounts, Nginx/443 paths, certificate/SNI, Panel/Node UUID and
   secret permissions, replay storage, encryption master backup.
4. FRP, Backhaul and XHTTP traffic, signed registration, Apply/Remove,
   client routing, reboot persistence, provider snapshots and rollback
   have NOT passed actual two-VPS integration acceptance.
5. Standard mode only; Private Network remains out of scope.
6. Full review/merge of stacked Smite/U-OPTI PRs is separate from
   production deployment, version tagging and installer update.

## Direct route to first use

- **Gate A — Trusted test images:** publish immutable, reviewed paired
  OCI digests/attestations and use the U-OPTI source-parity gate to
  reconcile host overlays with them; make installer opt into this
  reviewed release explicitly, never default-upgrade production.
- **Gate B — Two disposable hosts:** rehearse IR installation, then
  KH installation, then 3x-UI, followed by dynamic port/path/tunnel
  creation through the wizard. Check negative HMAC/replay tests and
  actual FRP/Backhaul/XHTTP traffic in both directions with TLS/443.
- **Gate C — Promote:** demonstrate snapshot restore, reboot,
  fail-closed security and rollback before merging/tagging a
  user-facing version. Existing stable paths remain unaffected until
  approved cutover.

Do not use CI green as a date prediction. Each gate has objective
pass/fail criteria; a failed test means repair rather than pretending
the project is already deployable.
