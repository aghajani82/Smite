# Stage 10 — isolated, unpublished Panel + Node image smoke builds

**Draft image provenance groundwork; NO published image, no new version,
no live IR/KH deployment, no signed-mode activation.**

Earlier Smite drafts #2–#9 add Pairing, JWT UI, durable HMAC replay,
signed Agent controls, signed Node check-in/FRP and Admin Node security.
Until BOTH Smite container images are rebuilt from a reviewed branch,
the U-OPTI installer remains pinned to upstream Smite 0.1.7 image digests
and must not be assumed to contain any of those new features.

This stage adds a GitHub Actions matrix build that:

1. Builds the existing Panel Dockerfile from the current security branch.
2. Builds the existing Node Dockerfile from the same commit.
3. Uses a **local CI-only tag** (`smite-stage10-ROLE:ci`);
   does not push to GHCR, create a release, alter Compose, or run any
   application / gateway process.
4. Uses `docker create` **without docker start**, and `docker cp`
   to extract each image's `/app` source tree to a temporary runner path.
5. Checks security module presence, Python compilation and, for Panel,
   built React assets; for Node, presence of the strict Agent router guard
   and unauthenticated root liveness endpoint.
6. Emits local image IDs for log correlation, not registry provenance.

A build may fail for unrelated upstream binary or network download reasons,
because the current Dockerfiles download pinned FRP/Rathole/GOST/Chisel/
Backhaul assets during build. Such a failure does not authorize a workaround
that weakens security or silently alters binary provenance.

## Important distinction

**Building an image in CI does not establish a trusted production artifact.**
The exact local CI image digest is not the immutable GHCR manifest digest
that a future production host would pull. Release requires a separate
reviewed workflow with immutable image attestations, signatures/SBOM,
digest-pinned pairing of Panel+Node versions, and explicit U-OPTI
installer migration.

Existing U-OPTI deployments mount several host Python files over files
inside the images, including Panel `main.py` and Node
`panel_client.py`. Even a successfully built Stage 10 image can run
old insecure host overlay code. Companion U-OPTI Stage10 audit explicitly
flags these mismatches and never reports activation readiness.

## Activation remains HOLD

- Overlay reconciliation and signed gateway proxy preserving raw HMAC paths
- Root/service UID compatibility and protected identity/replay mounts
- Panel SQLite migration + separate Fernet master secret backup
- No anonymous registration, authorized Node lifecycle and Node→Panel checks
- Signed Panel→Node traffic and direct/FRP transport handling
- FRP, Backhaul and real XHTTP client traffic with snapshot and rollback
- Private Network mode separate release gate

**No action required on IR/KH until a coordinated activation review.**
