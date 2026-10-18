# Smite Node Pairing — Admin UI preview (Stage 4)

**DRAFT, no live deployment or server changes.**

This stacked branch adds the first visual flow to the existing Node pages.
It sits on top of the draft secure one-time pairing store and API:
Smite #2 (HMAC envelope) → #3 (SQLite issuance) → #4 (HTTPS pairing API)
→ this stage. The separately staged U-OPTI wizard is in U-OPTI #29.

## Behavior

- Both **Iran Nodes** and **Foreign Nodes** use the same modal.
- A JWT-authenticated `GET /api/node-pairing/capabilities` probes configuration
  and schema read-only; the response contains only Boolean readiness flags.
  The endpoint reports `legacy_node_auth_enforced=false` because **the
  existing Node registration/Agent endpoints are not authenticated yet**.
- By default `SMITE_NODE_PAIRING_PREVIEW_ENABLED=false`, so no Pair button
  appears. It also stays hidden on missing/misconfigured encryption key,
  missing ingress proof secret, invalid JWT, missing DB tables or older API.
- If the explicitly configured preview is ready, a `Pair (preview)` action
  appears by each Node in its table. Admin verifies the Node ID, role and
  host outside the untrusted legacy registry, checks confirmation and then
  requests a one-use, 600-second code from the JWT-protected Panel API.
- The code only exists in local React modal memory; there are no persistent
  browser writes, QR / secret-bearing URLs, app logs, telemetry or automatic
  copies. Code view is cleared on modal close/unmount or expiry.
  Copy-to-clipboard requires a click and carries a warning that the OS
  clipboard must be cleared afterwards.
- No new public listening ports or routing changes. No Node/FRP/Backhaul
  container lifecycle is touched. No existing registration API removed.

## Important security limitations

- **Not an enforcement rollout:** issuing a code does not sign, authenticate
  or otherwise protect legacy Node traffic. Never claim pairing enabled
  equals secure Panel↔Node.
- The current `GET /api/nodes` and Node registration may disclose
  information / allow unauthorized changes; this is a known independent
  issue. Move admin listings to JWT, update the U-OPTI Foreign Gateway's
  anonymous discovery and implement two-way HMAC before enabling strict mode.
- A browser copied code may linger in OS clipboard, browser extension
  memory, screenshots or crash captures even after modal closure.
- Master and ingress secrets must be provisioned separately. The Node
  enrollment reverse proxy must strip any user-provided ingress header and
  inject a protected one, apply rate limits and allow TLS/443 only.
- U-OPTI currently has only a standalone **preview**, not a live secure
  pairing and signed-request integration. Host bind mounts shadow
  `panel/main.py`; this UI must be included in the matching Docker
  frontend build and compatible Panel overlay before being tested on VPS.
- Existing insecure `httpx.verify=False` in the legacy Node registration
  client is not changed by this PR and must not carry credentials.

## Validation

`.github/workflows/node-pairing-admin-ui.yml` tests frontend TypeScript
typechecking and production build, plus offline FastAPI/JWT
capability and one-use redemption tests and static no-persistence checks.
This is not a browser security penetration test.

**No user commands yet. No PR merged.** Next work: signed registration and
HMAC-authenticated Panel ↔ Agent commands, authenticated Node discovery,
Nginx ingress config and U-OPTI install/pairing automation with rollback.
