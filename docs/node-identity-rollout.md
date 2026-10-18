# Smite Node identity: design and staged rollout (2026-10-18)

> **Status: CODE FOUNDATION ONLY — NOT ACTIVE SECURITY.** This branch adds
> authenticated request-envelope primitives and offline tests. It does NOT yet
> protect /api/nodes or /api/agent, provision secrets, pair machines, or deploy
> to the user’s IR/KH servers. Do not merge/release as a complete Node-auth fix.

## What the live test confirmed

- Admin-panel API JWT guards work **after** U-OPTI's host bind-mounted
  `/opt/u-opti-smite/panel/main.py` is patched (a custom Docker image alone
  does not override the bind mount). The operator confirmed login/UI and tunnels.
- Both Standard-mode Smite Node APIs now listen **only on 127.0.0.1:8888**,
  persistently via Docker Compose (U-OPTI draft PR #28); both are healthy.
- Panel reports `node-ir` and `node-kh` as `active/connected`. The public
  data-plane still enters via HTTPS/443, Nginx and the established FRP/Backhaul
  gateway routes. No claim is made about end-to-end client tests after restart.

## Critical remaining problems in upstream code

1. `POST /api/nodes` accepts self-asserted IP/port and updates an existing
   record keyed by a fingerprint derived from IP/port, with no authentication.
   Its response may include a **usable FRP token**. This must not stay public.
2. `GET /api/nodes`, `GET /api/nodes/{id}` and `DELETE /api/nodes/{id}`
   have no admin JWT guards. However U-OPTI's Foreign Gateway readiness
   currently fetches `GET /api/nodes` anonymously; update the helper before
   enforcing access on this route.
3. `PUT /api/nodes/{id}/frp-status` accepts unauthenticated status changes.
4. Node Agent `/api/agent/tunnels/apply`, `/remove`, `/status` accept
   unauthenticated requests. Even loopback-only binding is no substitute for
   verifying *the Panel's identity* across the HTTPS/443 reverse proxy or FRP.
5. Node's `httpx.AsyncClient(verify=False)` disables server certificate
   validation. Credential-bearing requests MUST switch to verified TLS.
6. A web-dashboard admin JWT is the wrong credential for a headless Node.

## Target protocol

- Keep public **80/443 only**, node API on 127.0.0.1 in Standard mode,
  and existing private/internal backends closed to the WAN. Private Network
  mode currently has a separate direct-private-IP design; do not change that
  listener until private control routes and healthchecks are migrated.
- Enrollment is admin-approved and short-lived: create a one-use, scoped,
  expiring pairing credential **on the Panel**, transfer to KH via a guided
  U-OPTI wizard, and exchange once over certificate-verified HTTPS/443. Store
  **only the enrollment-code hash** in the Panel DB; consume atomically.
- Each Node persists its assigned UUID and high-entropy unique secret in a
  root-only file or equivalent restricted Docker secret. Server-side lookup
  must bind to that UUID; never trust self-reported IP/role/fingerprint alone.
- The Panel must securely retain or derive a **unique per-node secret** from
  a protected Panel master; do not put node secrets in `NodeResponse.metadata`,
  `/api/settings`, logs, URL query strings, FRP configs or general status.
- All machine-to-machine control requests get the canonical v1 HMAC envelope:
  `VERSION + node_id + HTTP method + exact path/query + timestamp + unique
  nonce + SHA256(raw body)`. Reject invalid signatures, stale timestamps,
  repeated nonces, unknown/revoked nodes and replay cache overflow. Provision
  NTP/time sync; respect path rewriting from HTTPS/443 reverse proxy.
- For a **single-process** worker, this branch's bounded in-memory `NonceWindow`
  works as a testable primitive. Production deployment with multiple workers,
  instances or restarts needs a *shared atomic* replay store and a strategy for
  process restarts; do not claim cluster-level replay protection otherwise.
- Healthcheck `/healthz` can return minimal public/localhost health (no tunnel
  details); `/api/agent/status` and all control APIs should require Node auth.
  Update Docker Compose healthcheck and Panel status client together.
- Authenticate BOTH directions: Node register/re-register/FRP status to Panel,
  and Panel get-status/apply/remove to Node. Keep an explicit deny-by-default
  policy for unknown/revoked nodes.
- Limit login/enrollment attempts, audit sensitive operations without logging
  secrets, and provide token revocation/rotation + rollback.

## Safe implementation order

1. [x] **Envelope module and offline tests** — identical standard-library
   modules for Panel and Node; no router or service activation.
2. [ ] **DB model + admin enrollment workflow** — migrate without touching
   existing Node records, design idempotent/atomic one-time enrollment
   and race-safe consumption; scope by Node role/name/UUID.
3. [ ] **Node persistent identity + TLS validation** — no credentials sent to
   unverified servers. Implement U-OPTI guided pairing and secret storage.
4. [ ] **Shadow-only verification in Panel + Agent** — report readiness without
   changing existing traffic; observe both IR and KH.
5. [ ] **Authenticated clients and server route guards** — implement all
   directions; secure Node list/delete separately with admin JWT. Replace the
   Foreign Gateway's anonymous `GET /api/nodes` bootstrap check.
6. [ ] **Strict activation gate** — check all enrolled identities, valid
   control transport and signed calls first; switch endpoints to fail-closed
   without authentication fallback. Roll back only under isolated,
   operator-controlled maintenance.
7. [ ] **Disposable IR/KH live tests** — admin login, 443 gateway, Node status,
   FRP & Backhaul traffic, restarts, wrong/expired/replayed signatures,
   secret revocation, lost identity, private-mode compatibility.
8. [ ] **TOTP 2FA and panel-owned Backhaul lifecycle** in separate PRs.

## What this PR does NOT guarantee

Do not deploy this branch and claim Node endpoints are authenticated. The
current services are still legacy-unprotected; the user has provider firewall
and loopback plus Nginx IP allow-list as interim defense. Secrets potentially
exposed by the previously anonymous Panel settings/Node registration should
be rotated during the completed secured migration.
