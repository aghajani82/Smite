# Stage 12 — Administrator-pinned signed Node origins, controlled Backhaul edits

**Draft, off by default. No IR/KH deployment, TLS entrypoint change or main merge.**

## Removed signed Agent destination ambiguity

Old Node registration historically allowed unauthenticated metadata writes.
Accordingly, a value such as `Node.metadata.api_address` or
`control_address` is **not a trust anchor** for sending HMAC requests.
The signed Panel `NodeClient` now reads a separate out-of-band approved
per-Node identity file via `app.signed_node_origins.approved_node` and
**never consults legacy metadata/FRP ports for destination selection**
in signed mode. It checks the approved role against the Node record.

The approved file is a manually provisioned, service-user-owned JSON
file mode 0600 beneath a directory mode 0700. Its configured path is
`SMITE_SIGNED_NODE_ORIGINS_PATH` (default
`/etc/smite-panel/trusted-nodes/approved-origins.json`).
Schema example (documentation only, values NOT live):

```json
{
  "version": 1,
  "nodes": {
    "bbbbbbbb-1111-2222-3333-444444444444": {
      "role": "foreign",
      "node_name": "node-kh",
      "origin": "https://kh.example.org:443",
      "control_url": "https://kh.example.org/hidden/control/"
    }
  }
}
```

The approved origin is a **hostname-verified HTTPS/443 bare origin**
with no URL userinfo/query/fragment/path. Exception: a locally
co-located IR Node may use only `http://127.0.0.1:8888` if explicitly
approved as role `iran`. No remote cleartext, arbitrary TLS port, IP
literal, automatic retries or fallback to unsigned legacy metadata.
Future FRP-loopback control endpoints need explicit trust + provenance
work and are intentionally not inferred from anonymous legacy state.

The existing signed machine gateway self-check compares the KH Node's
claimed name/control URL to the **admin-pinned** identity after safe
URL canonicalization, not merely to its legacy metadata record.
Approval files are NEVER written from self-registration or an
unprotected Panel API route.

## Standard Backhaul update changes

`review_backhaul_edit` validates an existing Standard Backhaul opt-in
before spec changes are committed. It rejects removing the opt-in or
altering loopback-only mapping/WS/tokens/ports in unsupported ways.
When updating a Standard Backhaul tunnel, the Panel does not restart
its own duplicate Backhaul server: IR Node owns that listener.
Legacy non-Standard Backhaul and FRP paths remain unchanged.

Stage 11 already ensured signed/legacy `NodeClient` both normalize
persisted Standard Backhaul Apply payloads; Stage 12 protects edit time
rather than allowing an unsafe spec into storage first.

## Nginx gateway risk and companion U-OPTI plan

The legacy hidden KH ingress uses a trailing-slash
`proxy_pass http://127.0.0.1:8888/;` under a custom URL prefix.
That URI replacement is **not suitable for HMAC** on the exact
`/api/agent/...` target. Companion U-OPTI Stage 12 provides a
private, inert proposed KH location using
`proxy_pass http://127.0.0.1:8888;` (no URI suffix) for
`/api/agent/` with narrow source-IP ACL and a maximum request body.
It is NOT inserted into the active vhost and must be reviewed in
the actual TLS/SNI/domain context. DNS-only/direct and Private
Network/Cloudflare-proxied cases need separate validation.

## Before coordinated IR/KH tests

- Pin trusted Panel+Node security images by immutable registry digest;
  reconcile old FRP/Backhaul overlays and container runtime UID.
- Manually approve exactly the paired Node UUID, name, role,
  hostname, control path and trusted source IP; no untrusted
  self-registration can perform that approval.
- Provision private Panel origin file via container-safe read-only
  mount; ensure the running service UID can read it without
  widening file permissions. Back up the Fernet master.
- Prove Nginx request target and query preserved across TLS/443
  (including allow/deny policy), as well as HMAC header forwarding.
- Confirm new authenticated registration/FRP heartbeat, Apply/Remove,
  reapply/update and real user FRP/Backhaul/XHTTP traffic.
- Verify snapshot and rollback behavior, including reboot.
- Private mode is out of scope.

**CI only verifies offline source and mocked runtime branches.
It is NOT permission to enable `signed` on real hosts.**
