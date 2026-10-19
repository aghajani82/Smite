# Independent tunnel engines — first inventory contract (review-only)

Smite Core's new managed mode does not assume that a bundled executable
means that FRP, Backhaul, GOST, Rathole, or Chisel is installed.

- Default **legacy** mode retains all existing Stable behavior.
- In **managed** mode, a new Node starts with all engines
  `not-installed`; `GET /api/agent/engines` is signed HMAC-only in
  the clean rollout and is read-only.
- A future installer may explicitly register one engine with a
  root-owned, 0700 state directory and 0600 `engines.json`:
  `{"schema":1,"engines":{"backhaul":{"sha256":"<64 hex SHA256>"}}}`.
  The actual in-container executable must be root-owned, non-writable
  by group/others, executable, and SHA256-identical. No external
  URLs, arbitrary binary paths or module install actions are allowed
  in the manifest.
- Invalid/tampered registry fails closed. A legitimate empty registry
  is a normal state. The signed Agent refuses tunnel Apply with 409
  before calling an adapter unless the selected engine is `ready`.
- This is NOT yet the installer. Neither the Panel nor the Node
  automatically modifies `engines.json`, mounts engine binaries or
  starts engines. A future U-OPTI per-engine lifecycle installer must
  create and atomically update it after independent download/hash
  verification, safely mounting the desired binary and rollback.
- An engine being `ready` is distinct from being **running** or
  **reachable** on a 443 route. The Panel's tunnel creation UX still
  needs managed admission + per-node readiness checks before any
  activation. All public ports and existing tunnels are unchanged.

Never deploy the managed mode to a real VPS until those remaining
gates and two-host acceptance pass.
