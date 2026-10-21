# Stage 3 — Pairing preview API and verified-HTTPS Node client

**Status: DRAFT. Do not enable, merge or deploy this independently.**

This branch is stacked on Node identity HMAC (#2) and the one-time code +
encrypted SQLite secret store (#3). It adds the first HTTP application adapters
and an opt-in Node enrollment client but **does not secure the live legacy
registration/control endpoints**.

## New endpoints (mounted in the image, disabled by default)

- `POST /api/node-pairing/issue`: requires **admin JWT** through
  `Depends(auth.get_current_user)`. JSON includes an existing Node UUID,
  registered role and expiry (60–900s); responds with a one-time code and
  expiry, shown only to the authorized admin. No unguarded GET issuance.
- `POST /api/node-pairing/redeem`: uses one high-entropy, role-bound,
  expiring code. This endpoint has **no admin JWT** because a headless node
  will redeem through the securely provisioned code, but it requires a
  **trusted HTTPS/443 proxy proof** `X-Smite-Pairing-Ingress` checked in
  constant time. Nginx MUST *strip and overwrite* any client-provided
  header, inject the secret only on the designated pairing route and
  enforce rate limits and body size limits.
- Both use a separate encrypted master key. Node secrets are never exposed
  by `/api/nodes`, other metadata or admin listing and must not be logged.

## Default-off controls

Panel environment settings added:

- `SMITE_NODE_PAIRING_PREVIEW_ENABLED=false` (the default)
- `SMITE_NODE_PAIRING_MASTER_KEY` — separate persistent Fernet master
- `SMITE_NODE_PAIRING_INGRESS_TOKEN` — separate random proxy-to-backend
  secret at least 32 characters, NOT the admin JWT or FRP token

Unless deliberately provisioned, the endpoints return `503`; unmatched
gateway proof returns `403` even if the code is valid. No schema migration
is performed at import/startup; a later backup and migration step must
explicitly run `node_pairing_store.initialize_schema`.

**Deployment details not yet implemented:** Nginx trusted-header injection,
strict rate limiting (for both username and pairing IP), explicit origin
policy, secure key distribution/rotation, U-OPTI wizard interaction, updated
`/api/nodes` readiness check, signed heartbeat and tunnel command enforcement.

## New Node pairing client

`node/app/pairing_client.py` is **NOT imported by existing Node startup**.

- Requires an exact `https://hostname[:443]` Panel base URL; no other
  scheme, host credentials, path, query, redirect or HTTP fallback.
- Calls `httpx.Client(verify=True, trust_env=False, follow_redirects=False)`;
  it does not call the legacy `PanelClient(verify=False)`.
- Sends the pairing code only in JSON POST body, never URL or logs.
- Stores JSON identity file as 0600 in an already provisioned 0700 owned
  directory, with exclusive create (never overwrites an existing key).
- Validates node UUID and 256-bit secret format; declines if the stored
  UUID differs from what the endpoint returns.
- The wizard must create the secure directory **before** beginning pairing.
  A failed disk write after successful redemption consumes the code and
  requires an explicit admin recovery workflow.

## Important existing problems

- Original Smite may accept anonymous register/re-register and return FRP
  control tokens. This remains unchanged in this branch.
- The host U-OPTI bind-mount shadows `panel/main.py`; the new route must be
  added to a compatible Overlay integration **before** a live test.
- The pinned Node image does not yet contain the new enrollment client. A
  U-OPTI module or staged custom image must provision it and machine
  credentials before any strict Node guard can be enabled.
- `PanelClient(verify=False)` must be migrated or restricted in the later
  phase; this new client's HTTPS verification does not fix other requests.
- A pre-existing unauthenticated legacy Node record is NOT sufficient proof
  of hardware/node identity. Admin must verify role/host out of band before
  issuance. Key replacement, lost/rotated keys and database backup need
  separate workflows.
- Keep Standard Node ports bound on `127.0.0.1:8888`; Nginx 443 remains the
  single network entry. Private Network remains a separate rollout.

**No live IR/KH containers have been modified by this branch.**
