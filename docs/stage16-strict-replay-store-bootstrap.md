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

## First paired-Node provisioning: now implemented, offline and opt-in (2026-10-20)

[Existing Smite Draft #16](https://github.com/aghajani82/Smite/pull/16)
now includes `node/app/replay_enrollment.py` and negative regression
`tests/test_replay_enrollment_offline.py`. This is **not** an HTTP
endpoint, server startup hook, automatic pairing or an enabled release.

1. The operator must **already** have a paired private Node identity,
   with strict 0600 file, owned by the current Node process UID, inside a
   0700 owned, persistent identity directory. The replay database lives
   in a **separate** 0700 owned persistent directory. Both paths must be
   absolute and neither existing state nor symlinks may be overwritten.
2. **Explicit** `--confirm-first-provision` is mandatory. The helper
   reads the existing Node ID without printing its secret.
3. Before creating any SQLite file it durably writes a 0600
   `replay-enrollment.json` marker **next to the identity**, on the
   identity's independent persisted volume; this contains only schema,
   Node ID and replay path. It is **not a credential**.
4. Only then call the reviewed `DurableNonceStore.initialize_new()`.
   The helper checks the same paired identity still exists and that
   the created SQLite identity matches the approved Node.
5. Any existing marker, database or ambiguous permissions result in
   **HOLD**. A partially failed first enrollment keeps the marker and
   any SQLite state for **manual review**. No automatic deletion,
   recreation, key rotation or recovery command exists.
6. The marker survives loss of the **replay DB volume alone** if the
   independent identity volume survives, so a second attempt cannot
   misinterpret DB loss as first boot. Loss/rollback of **both** volumes
   and stale **same-Node** replay snapshots remain unresolved risks.

No command should be run on current IR/KH. For a separately approved,
disposable **KH sandbox** only, the future operator invocation format is:

```bash
# KH — APPROVED DISPOSABLE SANDBOX ONLY. NOT FOR LIVE IR/KH.
python3 -m app.replay_enrollment \
  --identity /etc/smite-node/identity/node-identity.json \
  --replay-db /var/lib/smite-node/auth/agent-replay.sqlite3 \
  --confirm-first-provision
```

Both parent locations must already be securely mounted, writable,
owned and 0700; **this tool does not create those mounts or directories**.
It does NOT change `SMITE_AGENT_AUTH_MODE` from its default `legacy`,
restart services, reach the Panel, or authorize activation.

CI checks explicit opt-in, no secret logging, first bootstrap success,
one-time denial, later DB-loss rejection, failure halfway through
provisioning, unsafe permissions/symlinks and valid signed nonce replay
persistence. This is supported by the existing strict Agent test workflow.

## Restored-snapshot quarantine — fail-closed implemented; release still HOLD (2026-10-20)

The reviewed Node HMAC validator accepts timestamps within
`MAX_CLOCK_SKEW = 90` seconds of the receiver's clock. A stale
same-identity SQLite snapshot can omit accepted nonces; matching
`node_id` and schema alone **cannot detect that rollback**.

In the existing Smite Draft #16, `node/app/replay_restore_hold.py`
implements a deliberately **one-way offline quarantine** for
*known/declared* restores. With explicit operator confirmation, on an
**offline and stopped** Node/signing path it reads the original private
identity and first-enrollment marker, checks their matching Node ID and
database path, and durably writes private `0600`
`replay-restore-hold.json` **beside the identity**, outside the Replay
SQLite volume. No nonce or secret is logged. Signed Agent request
verification checks this hold **before reading/registering nonces**:
existing, malformed, mismatched or symlinked markers cause **503**,
including across app/container restart. The command cannot clear the
hold, initialize/restore SQLite, rotate keys, restart services, or
auto-enable strict mode.

This is **not automatic stale-snapshot detection**: a restore bypassing
the operator quarantine (especially a restore of BOTH identity and
replay volumes) is not proven safe. Nor does waiting `2 × 90` seconds
automatically unlock the Node; clock trust, signer shutdown, review and
an independently authorized recovery/paired key-rotation protocol are
still necessary. **The quarantine marker intentionally has NO
automatic release path.** The runtime may resume only after a separately
designed, reviewed and tested authorization procedure.

Verified in CI: old SQLite snapshot copied back for the SAME Node
after a consumed nonce; a marked restore denies both old and fresh
signed nonces; malformed markers also fail closed. The U-OPTI
integration additionally checks HTTP 503 and refuses the signed
Compose admission while quarantined.

Never fix a missing/failed nonce database by silently creating a new
blank one. No production Snapshot restore/migration procedure is
approved; do not run on current IR/KH.

Do not provision this on current IR/KH nodes. The existing U-OPTI
installer and container mounts do not yet integrate this **explicit**
operator-only bootstrap, mount admission or a safe **restore lifecycle**.
The new `node/app/replay_enrollment.py` tool is an offline first-boot
primitive, NOT a production installer or recovery procedure.

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
