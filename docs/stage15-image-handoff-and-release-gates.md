# Stage 15 — Unpublished, source-locked two-image Docker test bundle

**This is the first paired binary handoff, NOT a release or a deployable
security image.** Proposed label: `2.0.0-rc.0`; no tag or GHCR push.

The workflow `.github/workflows/stage15-offline-image-bundles.yml`
builds both Panel and Node from **the exact same GitHub Commit**.
It smoke-checks the required security source files *inside* each image.
A second GitHub Actions gate then runs both images as disposable, isolated
containers (Docker network mode `none`, no published host ports, no host
volume mounts, read-only root and temporary data mounts). It checks Panel
HTTP readiness, static UI, version, zero-state API counts, MFA database
columns, rejection of anonymous login, and the Node's local liveness.
Only if these pass does CI create:

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
   KH. Passing the new isolated CI first-boot test is not a substitute for
   a real two-host install. Future acceptance must verify image/container IDs and
   bind mounts, Nginx/443 paths, certificate/SNI, Panel/Node UUID and
   secret permissions, replay storage, encryption master backup.
4. Node registration is deliberately *not* tested: the isolated Node
   cannot reach a Panel, and no HMAC/tunnel communication is activated.
   FRP, Backhaul and XHTTP traffic, signed registration, Apply/Remove,
   client routing, reboot persistence, provider snapshots and rollback
   have NOT passed actual two-VPS integration acceptance.
5. Standard mode only; Private Network remains out of scope.
   **Stage18 pre-enrollment:** Admin-only `POST /api/node-pairing/reserve`
   creates a PENDING Foreign Node ID with no IP address or external
   registration. The preview flag, valid private Fernet master and migrated
   pairing tables must all be present. Admin can then issue a short-lived
   pairing code to the reserved ID using the existing UI and store.
   It does NOT pair the Node, switch to signed mode, contact KH, or
   open any ports; HTTPS/443 gateway admission remains separate.
   The fresh **Foreign Node** can now boot in `paused` Panel auth mode:
   it deliberately does not call the legacy unauthenticated HTTP/8000
   registration endpoint. Agent API can be strict before pairing, with
   rejected requests until a private identity is provisioned. This is
   a **pending-pairing install state**, not an established connection.
   Turning on `signed` requires a separately reviewed provisioning flow;
   never change to `legacy` to make the UI show Connected.
6. Full review/merge of stacked Smite/U-OPTI PRs is separate from
   production deployment, version tagging and installer update.

## 2026-10-20 — exact Panel/Node OCI image source revision gate

The *existing* unpublished `stage15-offline-image-bundles.yml`
now builds both images from one exact reviewed PR source SHA using
`--build-arg SMITE_SOURCE_SHA="$SMITE_BUILD_SOURCE_SHA"`. The final
Panel and Node Dockerfiles embed the source in their
`org.opencontainers.image.revision` label, plus an explicit
`smite.role=panel|node` label. The same workflow reads **real**
`docker image inspect` data before first-boot tests and **before**
creating any `docker save` archives.

`tests/stage15_image_revision_gate.py` rejects missing, incorrect or
mismatched revision SHA, wrong/swapped role, wrong version, duplicate
image IDs and malformed inspect metadata. The separate regression
`tests/test_stage15_image_revision_gate.py` requires fail-closed
behavior and checks the workflow actually passes the exact source SHA
to **both** builds. Both Dockerfiles still default their revision
build arg to `unverified` unless a reviewed pipeline explicitly sets
it, preventing an implicit claim of provenance.

This proves the **local image metadata matches the source reviewed
by the CI checkout**. It does **not** prove an independently signed
OCI registry digest, reproducible third-party base layers, or that
someone cannot forge image labels on another build. The images
remain **UNPUBLISHED/NOT PRODUCTION-ADMITTED**, with no GHCR push,
Docker load on IR/KH, release tag or runtime activation.

Test: [Stage15 CI run 39439403024](https://github.com/aghajani82/Smite/actions/runs/39439403024)
(the full paired-image build may outlast the fast unit-tests; verify
its final state before reporting all jobs PASS).

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
