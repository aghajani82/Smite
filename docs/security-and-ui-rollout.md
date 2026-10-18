# Security hardening: staged rollout

## Reproduced exposure (October 18, 2026)

Freshly deployed Smite v0.1.7 returned HTTP 200 from the public
`https://iran01.kolbe1.ir/api/tunnels` and `/api/settings` without a
Bearer token. The local `127.0.0.1:8000` bound listener is not reachable
from the internet, but the managed HTTPS/443 gateway proxies to it.

## Phase 1: admin API authentication (THIS PR)

Require the existing Smite JWT user dependency on **all methods** of
`/api/tunnels`, `/api/settings`, `/api/logs`, and `/api/core-health`.
React already sends this JWT when logged in. Runtime tests ensure anonymous
requests fail and that every registered route within these groups is covered.

Preserve the existing internal `/api/status` healthcheck (Smite Docker health
depends on it), version endpoint, certificate bootstrap and Node enrollment/
heartbeat until there is a separately designed and tested Node authentication
upgrade. **This is not complete system-wide API hardening:** other routes,
especially `/api/nodes`, require an explicit protocol migration. Do not
claim the overall Smite admin surface is fully secure or deploy to production
before an audit of those remaining routes.

### Safe rollout conditions

- No current VPS, Docker image, Nginx gateway, FRP or Backhaul service is
  changed by this GitHub PR.
- Run the isolated CI tests, then build a uniquely tagged image on a disposable
  trial VPS. Never change the pinned Smite image in U-OPTI main just to try
  this patch.
- Confirm 401/403 on the four API groups with no token, 401 with invalid
  token, and successful UI operations with a valid admin token.
- Confirm Node registration/reconnect and Smite healthchecks still work, then
  retest FRP/Backhaul connectivity and reboot persistence.
- Inventory `/api/nodes`, panel CA, status and agent endpoints. Introduce
  dedicated authenticated Node credentials before locking them down.
- After *complete* authentication changes and a safe rollout, rotate panel,
  tunnel and bot secrets that might have been exposed. Never paste them in a
  GitHub issue or chat.

## Phase 2: TOTP and UX (NOT IMPLEMENTED)

Design optional enrollment with an authenticated, short-lived setup session,
TOTP secret encryption at rest, verified activation code, recovery codes shown
only once (hashed server-side), step-up verification on disable, generic login
errors, login throttling, and a tested lost-device recovery flow. Existing JWT
sessions must not be allowed to bypass a newly enabled MFA policy; plan
session revocation/versioning.

Separately adapt the Smite React sidebar: a smaller logo, reduced empty header
height, scrollable navigation, and a clear footer across laptop/mobile widths.

Do not ship a UI-only OTP field or consider it 2FA without server-side
enforcement.
