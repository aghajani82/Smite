# Stage 2 — Smite Node pairing store (draft, disabled)

> NOT DEPLOYABLE ALONE. No HTTP endpoints invoke this code yet. It adds
> atomic, encrypted persistence primitives only. Existing Node endpoints
> remain unauthenticated until a coordinated Panel, Node and U-OPTI migration.

## New service

`panel/app/node_pairing_store.py` uses the existing SQLite DB file through a
separate, opt-in migration. It does not modify the legacy `nodes` table.
`initialize_schema(database_path)` must be explicitly invoked by a later
migration step, after database backup. It is not run at import or startup.

- Admin approves one **already-listed node UUID** and its **iran/foreign** role.
- Generates a 256-bit random `smn1_` code (shown only once to that admin).
  Stores only a SHA-256 digest with domain separation, the node UUID, role,
  issuing admin ID, issue and expiry timestamps.
- Expires in 60–900 seconds, default 10 minutes. Issuing a replacement code
  invalidates the prior outstanding code for the same node.
- `redeem_code` uses SQLite `BEGIN IMMEDIATE` atomic transaction to verify
  code + UUID + role + expiration + unused status. It generates a fresh
  256-bit per-node shared secret, stores it encrypted using Fernet with a
  **dedicated, durable secret master** independent of the login JWT and FRP
  configuration; returns that secret **once** to the matched Node.
- Enforces one durable pairing per node. Separate operator-confirmed workflow
  is required for key rotation and lost credentials. Revocation prevents any
  further retrieval of the identity secret.
- `get_active_secret` is a private/internal server function only, never a
  JSON response model.
- No code or key is printed, sent in URLs, committed to GitHub or placed
  under Node.metadata.

## Prerequisites before wiring a public endpoint

1. **Review legacy unauthenticated registration**: `POST /api/nodes` can
   create/modify node records and reveal an FRP control token. Do not use a
   legacy record as a trust anchor until a logged-in admin verifies the Node
   identity through an out-of-band channel. Disable that legacy route only
   after Node registration and U-OPTI compatibility is ready.
2. **Verified TLS**: Node currently creates HTTPX with `verify=False`.
   Change Node transport and SNI chain to verified HTTPS/443 before any
   enrollment codes or keys are submitted. Keep `127.0.0.1:8888` on
   Standard-mode nodes, Nginx allow-list, and existing gateway route.
3. **Admin-only issuance API**: use `Depends(auth.get_current_user)` on
   provisioning routes, with CSRF/origin controls for browser token storage,
   `Cache-Control: no-store`, aggressive rate limits and an audit event
   containing only node ID/admin ID, never the raw code.
4. **Node pairing client**: persist UUID and secret with mode 0600 in a
   root-owned protected file; never include in Docker logs or the regular
   Node responses. Send one-time approval code over a TLS-verified
   channel, not a URL query. Implement startup re-enrolment/FRP heartbeat
   with HMAC signature from Stage 1 and no silent downgrade.
5. **Panel-secret management**: provision separate persistent Fernet master
   via a protected deployment secret and backup key recovery separately.
   Rotation needs an explicit audited re-encryption/rollback plan; losing
   the master means encrypted Node identities cannot be recovered.
6. **Panel API and Agent**: replace unsigned registration, FRP heartbeat,
   status, apply/remove flows with authenticated alternatives. Protect
   GET/DELETE nodes with admin JWT; update the U-OPTI foreign gateway
   discovery helper, which currently reads `GET /api/nodes` anonymously.
7. **Shared anti-replay store** for multi-worker deployment; Stage 1 in-memory
   replay window is only appropriate to an isolated single-process test.
8. **Private Network mode** currently depends on private TCP/8888;
   do not switch it to loopback until a private control/443 migration exists.

## Planned live test — not performed

- Snapshot disposable IR and KH, preserve panel SQLite and Compose.
- Provision signed enrolment in staged mode and verify test Node identity.
- Ensure Panel↔Node and HTTPS/443 gateway work, including FRP config and
  Backhaul Sidecar traffic; simulate wrong/expired/replayed tokens.
- Rollback without exposing or downgrading any Node identity.
- Only after proof, enable fail-closed Node authentication (no legacy bypass).

No server changes are made by this GitHub branch.
