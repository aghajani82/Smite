# Smite — Simple Operator UI + MFA (Draft, no VPS changes)

The operator experience should feel like **three tasks**, not a server
administration course: add Iran Node, add foreign Node, then enter the real
3x-UI inbound port and create a tunnel. FRP and Backhaul are visible
choices; their advanced parameters are optional disclosures, not extra
mandatory setup menus.

## Included

- A smaller, responsive dashboard with three usage counts, CPU/memory
  progress bars and a three-step operator guide.
- Server registration state comes from the **actual** `GET /api/nodes`
  response, separate from the existing `/api/status` snapshot. Unlabeled
  nodes and API failures yield **unverified**, not fake readiness.
- Dashboard uses a truthful `Panel API responded` indication; it does
  NOT claim TLS/HMAC, tunnel routing or client traffic has been verified.
  Refresh failures display a visible warning and retain last-known data
  marked potentially stale instead of spinning forever.
- Four top-level navigation items: Dashboard, Iran, Foreign and Tunnels.
  Logs, Core Health and Settings stay accessible under an expandable
  **More tools** section. Direct routes auto-open that section.
- A simplified FRP / Backhaul *creation* form: name, both Node selections,
  transport, and explicit inbound port. The historic technical options,
  control ports, tokens and IPv6 remain available under
  **Advanced settings**; switching visibility does not reset their values.
  Existing tunnel editing remains fully advanced by default.
- Default tunnel creation core is FRP, but **no tunnel is automatically
  created**, and no Node or port is pre-selected.
- Port validation rejects blanks, duplicates, invalid numbers,
  copy/paste suffixes and out-of-range entries. Backhaul uses its own
  actual public/inbound port input, never silently falling back to the
  generic 8080. The form requires both registered server selections.
- Removed verbose Backhaul console output in the creation path and
  masked manually entered token inputs.
- Persian/English labels, keyboard focus visibility and RTL content
  direction; Pairing and transport-security
  logic are unchanged; the authenticated MFA endpoints are new.

## Not included / deliberately not claimed

- No new tunnel auto-setup endpoint, one-click FRP/Backhaul deployment or
  automatic HMAC activation. The UI is a shell over the existing tunnel
  API and is not a replacement for the U-OPTI post-install dynamic
  path/port wizard.
- **Real server-side TOTP MFA is included** in this branch. Login checks the
  password first, then requires a verified Authenticator or one-time recovery
  code before issuing any access token. Invalid guesses are throttled after
  five attempts. Enrollment requires the current password and a valid
  6-digit authenticator code, with Fernet-encrypted secrets and ten hashed
  single-use recovery codes. Enabling/disabling MFA invalidates older JWTs.
  MFA setup requires a strong deployment SECRET_KEY; the U-OPTI installer
  already generates one. Sensitive setup/login responses have no-store headers.
- Google Authenticator supports manual entry of the displayed setup key.
  A local QR renderer is not yet included; do not send provisioning secrets
  to third-party QR services.
- This is **not yet a fully audited production authentication system**:
  HTTPS, login-IP throttling at the gateway, secure backups of the SQLite
  database and cross-process concurrency/recovery rehearsals still need
  verification. No claim of final live readiness is made.
- No claims that an active Node means end-to-end client traffic passed.
- No modifications to existing IR/KH VPS hosts, nginx, Docker, credentials
  or live FRP/Backhaul tunnels.

## Tests

`.github/workflows/simple-operator-ui.yml` runs `npm ci`,
full frontend TypeScript checking, node-native unit tests for strict
inbound port acceptance, source UI invariants and `npm run build`.
It also corrects a few existing frontend type declaration mismatches
and Vite static asset typing so the TypeScript gate stays enabled.

`.github/workflows/admin-auth-check.yml` runs the existing API permission
checks and `tests/test_totp_mfa.py`, including an RFC 6238 known vector,
password gate, enrollment, successful/failed login, TOTP replay rejection,
one-use recovery consumption, throttling and old-token revocation.

**Keep as Draft until the clean-install Panel image is built and
visually tested together with the new U-OPTI wizard on disposable hosts.**
