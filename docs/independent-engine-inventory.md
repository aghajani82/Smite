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
  **reachable** on a 443 route. Create Tunnel now shows the signed
  two-Node state and disables creation unless BOTH explicitly selected
  Nodes report `ready` in managed mode. A failed inventory probe
  fails closed; the legacy UI behavior remains in Stable.
- Managed create, spec-changing edit and single/bulk reapply are all
  gated server-side before their side effects. Reapply selects the
  original stored foreign Node, not the first available foreign Node.
- **Node restart restoration is also an activation path.** In managed
  mode, restoring previously persisted tunnels refuses a missing,
  invalid or unready enrollment before launching a tunnel process.
  Previously saved specifications are retained for future repair;
  they are not automatically destroyed. Direct internal adapter Apply
  checks readiness before removing any existing active configuration.
  Legacy mode retains its existing behavior. These checks are
  unit-tested in `tests/test_managed_engine_restart.py`.
  GOST (a forward-mode engine) also persists its explicit IR/KH pair
  when managed. No managed engine can be inferred from a bundled binary.
- UI readiness is a convenience only: the Panel rechecks on requests
  and each signed Node Agent rejects unregistered Apply. Engine
  inventory does NOT install software, guarantee network reachability,
  validate a 443 route or authorize production activation.
  All public ports and existing Stable tunnels are unchanged.

Isolated U-OPTI CI also starts the real Node API with the reviewed
source inside a pinned Docker image, network namespace disabled, no
published ports and strict signed Agent authentication. Before Backhaul
enrollment, a signed inventory returns `not-installed` and Apply is
HTTP 409; after a verified enrolled binary it returns `ready`. An
actual Docker restart preserves inventory and rejects replayed signed
requests; exact rollback returns to `not-installed`. This is a
throwaway-runner test, NOT a public 443 route or production deployment.

Never deploy the managed mode to a real VPS until those remaining
gates and two-host acceptance pass.
