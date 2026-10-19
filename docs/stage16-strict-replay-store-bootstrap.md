# Stage 6 — Explicit replay-store bootstrap and fail-closed recovery (DRAFT)

**2026-10-19. Experimental Smite-only branch**:
`feature/smite-strict-replay-store-admission-20261019`. This is stacked on
Smite Draft #15, **not main**. No release, container image publishing or
IR/KH migration/activation is authorized by this change.

## Problem addressed

Before this patch, each strict Agent request could call
`DurableNonceStore._open()` with `O_CREAT` and then
`CREATE TABLE IF NOT EXISTS`. A temporarily missing/removed persistent
SQLite database could therefore be replaced with a fresh empty replay
store. A previously used, still-timely signed nonce might then be accepted
again.

## New explicit lifecycle contract

- `DurableNonceStore.initialize_new(path, paired_node_id)` is a **one-time
  provisioning primitive** for use only by a future reviewed, offline,
  authenticated enrollment workflow. It requires a private 0700 parent and
  creates a 0600 database with `O_CREAT|O_EXCL|O_NOFOLLOW`.
  It creates the nonce table, a versioned schema, and a persistent
  `replay_store_identity` record for the paired Node. It does not expose
  an HTTP endpoint, CLI wizard or automatic startup initialization.
- `DurableNonceStore._open()`, used for incoming strict Agent requests,
  now opens only an already existing SQLite file with `mode=rw`.
  No request can create a database or recreate the nonce table. Missing
  file, empty DB, unknown schema, bad permissions, symlink or unreadable
  DB -> fail-closed `AgentAuthUnavailable`, surfaced as HTTP 503.
- Each `register(node_id, nonce, now)` transaction checks that the
  enrolled identity matches the authenticated Node before accepting a
  nonce. It continues to use SQLite `BEGIN IMMEDIATE` and a unique
  compound key for atomic cross-worker replay protection.
- An existing database always blocks re-initialization, even if empty
  or damaged. Operator intervention and a reviewed restore procedure are
  required; no automatic data-loss recovery or `rm` advice.
- Negative CI tests check missing database after a real signed request
  and across a new FastAPI instance, mismatched paired Node, empty schema,
  symlink, duplicate initialization, and normal replay concurrency.
  The existing legacy mode remains the default and unchanged.

## Recovery policy, **not** yet implemented

Never fix a missing/failed nonce database by silently creating a new
blank one during authentication. A restart must retain the same pairing
and persistent database, including all unexpired nonces. If missing:
quarantine/deny strict traffic, inspect provenance and restore a trusted
snapshot of the replay store plus the paired identity using a separate
authorized recovery transaction. Because a snapshot may be stale, a
future plan must either enforce a quiet period larger than the full
signature acceptance window after restoring older replay state, or rotate
the paired key before admitting traffic. The HTTP status remains 503
until an independently approved recovery is finished.

Do not provision this on current IR/KH nodes. The existing U-OPTI
installer and container mounts do not yet integrate a privileged,
idempotent first-enrollment and restore lifecycle. The Node
`node/app/agent_auth.py` primitive is not a production installer.

## Remaining limitations

- Same-UID adversarial races and an attacker with write access to
  the SQLite file or its private parent are outside this step's
  assurance. The runtime checks do not establish full filesystem
  isolation or cryptographic anti-rollback evidence.
- The stored ID is a pairing consistency check, not an authentication
  credential or authenticated network response.
- No proof of actual VPS snapshots, durable fsync after power loss,
  trusted TLS/443, Nginx target preservation, Docker/Node recreation,
  key backup/rotation or real-engine client traffic.
- The next U-OPTI sandbox compatibility test must use this *new* Smite
  SHA and explicitly provision the test replay DB; its older pinned
  Smite test source is intentionally left unchanged until coordinated
  integration. Do not silently change a pinned SHA in existing PRs.

**Activation remains HOLD. No main merge/release/IR/KH change.**
