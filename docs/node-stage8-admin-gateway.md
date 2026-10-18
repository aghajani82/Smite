# Stage 8 — Admin-only Node records and identity-scoped gateway readiness

**DRAFT, no live deployment or main merge.** Based on Smite #8 and the
other staged HMAC/Pairing changes. Coordinates with a separate U-OPTI
Foreign Gateway branch. All IR and KH services remain untouched.

## Security fixes

- `DELETE /api/nodes/{node_id}` now always requires the existing Smite
  admin JWT and real Admin DB lookup. An anonymous or forged JWT cannot
  delete a Node even while the old registration mode is active.
- `GET /api/nodes` and `GET /api/nodes/{node_id}` require the admin
  JWT **when `SMITE_NODE_REGISTRATION_MODE=signed` is enabled**. In
  default legacy mode the old API remains unchanged to avoid breaking
  the existing U-OPTI Foreign Gateway; this is a deliberately temporary
  exposure and is NOT security completion.
- A new machine-only `POST /api/node-control/gateway-check` uses the
  same paired HMAC, exact path and body, fresh timestamp, and persistent
  anti-replay store as signed Node registration.
- The server looks up the authenticated Node UUID; it compares only that
  Node's registered name, role and exact control URL and uses
  `NodeClient.get_tunnel_status` to assess the active control channel.
  Response is only `{"status":"ok","gateway_ready":true/false}`.
  It never enumerates other Nodes or returns FRP tokens, node metadata,
  IPs, secrets or administrative settings.
- Gateway self-check requires **both** Panel Node registration signed
  mode and Panel-to-Agent signed mode. Otherwise it returns HTTP 503.
  If the Node's HMAC is invalid/expired/replayed, it fails before reading
  any DB Node status.

## U-OPTI migration

Companion branch `feature/smite-paired-gateway-check-stage8-20261018`
uses a paired Node's mode-0600 private identity file to submit an
HMAC-authenticated self-check to the Panel over public-CA-verified
HTTPS/443 (with hostname checks, no redirects/proxies). Once an identity
file is present, U-OPTI **does not fall back** to GET /api/nodes on
failure. Existing unpaired legacy installs retain old verification until
the coordinated signed rollout, at which point anonymous listing closes.

This is a *transitional* state: do not enable signed mode until the
installer, Panel/Node images, Nginx gateway path, Panel host-overlay,
secret mounts, replay DB and FRP/Backhaul traffic have all passed tests.
An incomplete migration would intentionally fail closed and could show
Node disconnected; no user should be told to activate it early.

## Known remaining work

- Admin-confirmed enrollment for new Nodes and browser UI hardening,
  path-scoped Nginx gateway restrictions, rate limiting and source policy
- U-OPTI pairing wizard must mount the identity read-only into Docker,
  persist the replay DB and coordinate all relevant auth switches
- Signed gateway-check requires the Node control endpoint be reachable
  through the path preserved by the Panel's proxy. Real 443 tests pending
- Node revocation and deletion require coordinated lifecycle cleanup:
  deleting a Node row does not yet rotate/revoke its previously paired key
- Full inventory of unauthenticated legacy API routes beyond Node reads,
  TOTP, CSRF protections and JWT expiry tightening
- Private Network mode compatibility, snapshots, controlled fail-closed
  migration and rollback, real IR/KH FRP + Backhaul tests

No deployment or GitHub main modifications were performed.
