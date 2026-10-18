# Phase 6 — Signed Panel NodeClient (migration preview, default OFF)

**Draft only: Do not deploy to IR/KH, enable signed mode or merge as completed
security.** Built on stacked Smite draft #6 and earlier #2–#5.

## Implemented

- Real Panel `NodeClient.send_to_node` (Apply/Remove) and
  `NodeClient.get_tunnel_status` (aggregate status) have a separate,
  opt-in `SMITE_PANEL_AGENT_AUTH_MODE=signed` branch.
- Unlike Stage 5's standalone signer, this is connected to the actual Panel
  client entry points. The **default stays `legacy`**; the existing
  FRP/Backhaul control flow is unchanged until deliberate coordinated rollout.
- In signed mode, requests read per-Node HMAC key via the private encrypted
  identity store. The Node UUID must already be paired and not revoked.
  The key never originates from untrusted `node_metadata`, JWT or FRP.
- The Panel serializes POST JSON **once** and signs the exact bytes it sends.
  GET status likewise uses a signature. One attempt per call, no automatic
  Apply/Remove retry after an ambiguous timeout. No silent downgrade if
  pairing is missing, TLS fails, or Node replies 401.
- For off-machine control requests, the only permitted scheme is **HTTPS
  with certificate and hostname verification**, public port **443**, and a
  valid DNS hostname. Plain HTTP to off-machine Node API is explicitly
  rejected. An explicitly selected local FRP TCP endpoint may use HTTP at
  `127.0.0.1:port`; otherwise local Node is restricted to
  `127.0.0.1:8888`. No proxy auto-discovery, no redirects, userinfo,
  arbitrary path/query or custom TLS ports.
- Signing and transport errors return generic responses, not raw tokens,
  HTTP bodies, exception URLs or secret keys.

## Remaining blockers — DO NOT ENABLE ON SERVERS

1. U-OPTI wizard #29 currently stages a key only; it does not mount keys
   into the Node container or enable Stage 5's Agent strict guard.
2. The Node's existing registration and FRP heartbeat still use the
   legacy unauthenticated `/api/nodes` API, with `verify=False`.
3. Trusted HTTPS/443 ingress must forward an unchanged Agent target, with
   appropriately scoped Nginx access control, and the Panel registry
   must use an administrator-approved stable hostname. Avoid trusting a
   self-asserted IP from a legacy unauthenticated registration as authority.
4. The private per-Node key DB, persistent Fernet master and replay store
   need dedicated backup/recovery and rotation design, permission checks,
   proper mounts and operational preflight.
5. Both ends must switch together and fail closed, after verifying
   authenticated registration, signed status, apply/remove and FRP +
   Backhaul real-client traffic on two disposable VPS snapshots.
6. Distinguish Standard-mode localhost routes from Private Network mode;
   the latter needs a coordinated transport design.
7. Restrict Panel `/api/nodes` list/delete with admin JWT **only after**
   the U-OPTI foreign gateway bootstrap no longer depends on anonymous
   listing. Register/re-register requires separate machine auth.

This phase is **Panel→Node only**, does not complete mutual authentication
and does not render other legacy services safe. No active server changes.

## CI

`tests/test_panel_signed_nodeclient.py` checks real encrypted credential
retrieval, revocation, origin guard, byte-for-byte HMAC request submission,
no HTTP WAN/no TLS bypass, signed legacy API routing and secure defaults.
Network is mocked; the live 443 reverse-proxy and client tunnel paths still
need real tests.
