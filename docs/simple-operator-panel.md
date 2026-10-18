# Smite — Simple Operator UI (Draft, no backend or VPS changes)

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
  direction; functional API shapes, Pairing and transport-security
  logic are unchanged.

## Not included / deliberately not claimed

- No new endpoint, auto-setup API, one-click FRP/Backhaul deployment or
  automatic HMAC activation. The UI is a shell over the existing tunnel
  API and is not a replacement for the U-OPTI post-install dynamic
  path/port wizard.
- **Two-factor login is not implemented by this UI PR.** Real TOTP needs
  a server-side challenge, verified enrollment/confirmation, recovery
  codes, revocation and rate limits before a six-digit input is added.
  A mock code field would be actively misleading, so this PR does
  not pretend to add 2FA.
- No claims that an active Node means end-to-end client traffic passed.
- No modifications to existing IR/KH VPS hosts, nginx, Docker, credentials
  or live FRP/Backhaul tunnels.

## Tests

`.github/workflows/simple-operator-ui.yml` runs `npm ci`,
full frontend TypeScript checking, node-native unit tests for strict
inbound port acceptance, source UI invariants and `npm run build`.
It also corrects a few existing frontend type declaration mismatches
and Vite static asset typing so the TypeScript gate stays enabled.

**Keep as Draft until the clean-install Panel image is built and
visually tested together with the new U-OPTI wizard on disposable hosts.**
