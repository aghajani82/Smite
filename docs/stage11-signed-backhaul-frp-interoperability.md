# Stage 11 — Signed NodeClient + Standard Backhaul and opt-in FRP WSS/443

**DRAFT, off on live IR/KH. No production image pushed, no switch enabled.**

## Resolved conflict

U-OPTI's older Standard Backhaul patch injected canonical payload
normalization into Panel `NodeClient.send_to_node` AFTER the legacy DB
lookup. The new security branch returns EARLY for signed requests, so
that compatibility logic could silently be bypassed. This stage instead
places `prepare_node_command` BEFORE the signed/legacy branch. It
is used only when core=backhaul and endpoint=/api/agent/tunnels/apply,
and only compiles an IR/KH payload from an existing persisted tunnel
spec whose `uopti_standard_backhaul` opt-in is exactly true. A
requester's arbitrary spec cannot override the database token/ports.
FRP and other cores pass through unchanged.

The validated U-OPTI pure Standard Backhaul compiler is embedded
unchanged in both Panel/Node images (`app/uopti_backhaul_standard.py`).
The Node BackhaulAdapter validates opted-in specs **before** removing
an existing tunnel and protects the token-bearing TOML with 0600
permissions while omitting raw TOML from the opted-in log.

On Panel startup, Standard Backhaul no longer starts a duplicate
Panel-side listener when the IR Node is the intended server.

## FRP Standard WSS/443

U-OPTI's former FRP gateway helper and recognized FrpAdapter
transport transformations have been ported into Node image source.
They require explicit `SMITE_FRP_STANDARD_WSS=1` to use the
existing `PANEL_ADDRESS=trusted.panel.example:443` hostname and
WSS transport. **Default OFF** preserves TCP FRP behavior. A
custom port/SNI conflicting with the configured 443 hostname fails
closed. This stage does not edit Nginx or certify the effective
FRP ingress/control/data path.

## Important blockers

- Legacy U-OPTI host bind mounts can still shadow these image modules.
  Companion U-OPTI Stage11 makes a **manual review bundle**, not
  a production-ready mount.
- Existing U-OPTI `SMITE_CONTROL_ADDRESS` and
  `SMITE_BACKHAUL_ADDRESS` registration metadata patches remain to
  be integrated with secure administrator-approved node identities.
  The current signed registry intentionally rejects self-asserted
  metadata changes. Do not reintroduce unauthenticated registration.
- Legacy Smite route handlers besides `send_to_node`, including
  update/apply/reapply and custom Backhaul sidecar startup, still
  require signed-aware compatibility review and tests.
- A ready-made image is NOT proof of live signed transport. Image
  provenance/digest pinning, Panel SQLite/Fernet master migration,
  TLS/443 gateway, secret read-only mounts, replay storage, 3x-UI
  inbound routing, rollback and real FRP/Backhaul tunnel traffic are
  all still pending.
- Avoid enabling `SMITE_AGENT_AUTH_MODE=strict`,
  `SMITE_PANEL_AGENT_AUTH_MODE=signed`,
  `SMITE_NODE_PANEL_AUTH_MODE=signed`, or
  `SMITE_NODE_REGISTRATION_MODE=signed` on any live host yet.
- No FRP 443 switch or Docker image has been installed on IR/KH.

## Testing

`.github/workflows/stage11-backhaul-frp-compat.yml` tests byte-identical
compiler implementations, persisted-only opted-in payload selection for
IR/KH, fail-closed invalid/wildcard binds, NodeClient signed branch
integration, FRP default-off / explicit WSS, security hooks and
CI-only Panel+Node image extraction. CI cannot replace a real two-host
integration or traffic test.
