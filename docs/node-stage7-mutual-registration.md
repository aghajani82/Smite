# Stage 7 — Node → Panel signed check-in and FRP heartbeat

**DRAFT. Default OFF. Do not deploy to IR/KH, merge, or enable before the
coordinated installer/overlay/security rollout.**

Stacked after Smite draft #7. Completes a major code-path migration
prototype, not the full production security audit.

## Changes

- Node runtime gains `SMITE_NODE_PANEL_AUTH_MODE=signed` (default
  `legacy`). Signed mode **never creates the legacy verify=False HTTPX
  client**, sends registration and FRP heartbeat to a strictly verified
  HTTPS/443 Panel DNS hostname, and does not fall back to legacy on failure.
  The existing periodic 60-second registration loop still runs in signed
  mode even without a legacy HTTPX object.
- Panel gains two **machine-only** endpoints:
  `POST /api/node-control/register` and
  `POST /api/node-control/frp-status`. Both are **default disabled** behind
  `SMITE_NODE_REGISTRATION_MODE=signed` (default `legacy`).
- Existing approved Node UUID and role are checked against the DB. The
  Node signs method, exact path, timestamp, nonce and exact raw JSON bytes
  with a distinct paired secret. No self-declared IP/port/role overrides,
  no unauthenticated creation and no secret from browser Node metadata.
- Replay rejection persists in the Panel's SQLite DB with `BEGIN IMMEDIATE`,
  unique `(node_id,nonce)`, clock skew bound and fail-closed capacity.
  The table migration must be explicitly run *after backup* via
  `signed_node_registration.initialize_replay_schema`. It is NOT created
  on boot/import or the first live request.
- An authenticated check-in may receive necessary FRP config over HTTPS
  with no-store headers; FRP server hostname is from trusted Panel config
  `PANEL_DOMAIN`, never from a Node-supplied address. Missing or malformed
  FRP configuration stops this operation instead of disclosing or inventing
  a fallback.
- Once Panel's signed mode is switched on, old unauthenticated
  `POST /api/nodes` and `PUT /api/nodes/{id}/frp-status` return 403.

## Still incomplete: strict activation is prohibited

1. **Legacy GET/DELETE Node APIs are still anonymous**, and a number of
   status/settings routes require separate review. Move GET/DELETE to
   admin JWT, and update the U-OPTI Foreign Gateway anonymous Node
   discovery code. Otherwise enabling signed writes still leaves control
   plane holes.
2. **Enrollment is not a secure origin proof on its own**: existing legacy
   registered Nodes must be administrator-verified out of band, and new
   Node creation must use an admin authenticated workflow. The bootstrap
   Panel API/UI code and U-OPTI wizard are still staged and disabled.
3. **Node container identity mount is absent**. Stage 5 Agent strict
   mode and Stage 6 Panel signed mode must be switched together only
   after secure file mounts, same Node UUIDs, permissions, host-bound
   trusted TLS/443, Nginx path preservation, clock sync and replay DB
   persistence are validated.
4. Node's legacy `PanelClient.start` with `verify=False` remains present
   **only in legacy mode** for compatibility, and is not considered secure.
5. HTTP/443 gateway must expose Node->Panel signed routes through
   an appropriately limited path, apply rate limits and request size
   caps, and never turn internal ports 8000 or 8888 into public listeners.
   If a reverse proxy rewrites signed paths, requests will fail closed.
6. Reconcile the U-OPTI host bind-mounted Panel `main.py` overlay,
   and Node Docker images, plus Standard and Private Network mode
   semantics. Preserve existing FRP and Backhaul traffic.
7. Add safe key recovery/revocation and Panel Fernet master backup, full
   live IR+KH integration checks and verified rollback plans. Neither
   a green CI nor a successful offline signature is a live connectivity
   guarantee.

## Versioning plan

The current `frontend/package.json` has `version: 1.0.0` but this
does not establish the canonical Smite application version. Before
a release, add a central version source shared by Panel/Node/UI and a
CHANGELOG. Prefer a **single meaningful SemVer release** after full
integration and acceptance, potentially a new major version if
strict authentication changes the installer/protocol compatibility.
Do not artificially increment four or five tags just to represent the
number of draft security phases.

## Offline test coverage

- Panel: missing migration fails 503; unsigned/wrong key/stale/replayed
  requests rejected; role/UUID impersonation blocked; authenticated
  re-registration/FRP status; legacy anonymous writes rejected in
  explicit signed mode.
- Node: public CA-verified hostname HTTPS/443, exact HMAC payload
  and header matching, no HTTP/8000 fallback, signed runtime
  check-in and heartbeat and absence of legacy insecure client.

**None of these draft changes alter the user's two VPS or current
tunnel configuration.**
