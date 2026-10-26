# Smite XHTTP managed route — root transaction boundary (candidate)

**Status:** Host-side local transaction foundation and offline CI, **not integrated into the Smite wizard**, not a deployed one-click route service. No production runtime changes are authorized. Source branch targets the FRP multiport feature branch only.

## What the operator has today

The IR/KH disposable field trial has **real working** 45121 and 49328 XHTTP inbounds through one FRPS, two KH FRPC and TLS/443 Nginx. The existing IR Nginx routes are in `/etc/nginx/u-opti-smite-frp-xhttp.conf`. The two routes were installed manually with guarded operator scripts. **Do not replace, remove or import them automatically.**

## Ownership: no broad root access for Panel/Node

- IR host installer (future audited implementation) must explicitly provision a dedicated *root-owned* include path **within the approved HTTPS/443 server block**.
- Host-side managed directory: `/etc/nginx/smite-xhttp-routes`. Host-owned bridge include: `/etc/nginx/smite-xhttp-bridge.conf` with exactly `include /etc/nginx/smite-xhttp-routes/*.conf;`.
- The helper does not create or edit the bridge, the U-OPTI-owned routes, the top-level Nginx server, Panel config, or FRPS. Missing/incorrect bridge **HOLD**.
- The bridge must be audited for its *actual server-block scope* during installer bootstrap. Merely finding the bridge in `nginx -T` **does not prove** it belongs to the intended host/TLS 443 virtual server. This remains an **open pre-deployment gate**.
- Host-local root CLI: `scripts/smite_xhttp_nginx_transaction.py` is a separately reviewed prototype. It only accepts a fixed port + path, not paths to Nginx files, command templates or arbitrary upstream URLs. Its default is read-only; an administrator must explicitly opt into local apply. **Do not wire it to HTTP or sudo from Panel** as-is.
- The dedicated future transport is a separately authorized, minimum-privilege local broker carrying a narrow action/envelope from a verified signed IR Node, tied to the particular tunnel ID, KH Node, unique lease, signed KH inbound inventory and signed IR FRPS proof. It must not accept unauthenticated port+path strings, arbitrary local invocations from an untrusted container, or arbitrary Nginx source locations.

## Current local transaction checks

1. Root-only process. Refuses symlink, non-root or group/world-writable bridge and route directory.
2. Read-only `nginx -t` and `nginx -T`: approved bridge and active include required. Rejects collision with any observed numeric-port XHTTP location and with any Nginx upstream already pointing to this target port. It deliberately **refuses** an already-present unmanaged `49328` rule on the field trial host.
3. `ss -Hlntp` owner proof: the same FRPS PID owns `127.0.0.1:7000` and the requested proxy listener, with **no public-bind FRPS sockets**. This is a local safety cross-check; it is not a replacement for cryptographically signed Node proof.
4. A new only-once `<port>.conf` is staged with root-only permissions, atomically renamed, `nginx -t` performed, Nginx reload attempted, and all original FRPS sockets rechecked. Existing U-OPTI files untouched.
5. If validation/reload/socket proof fails, removes **only the new managed route** and tries to restore prior Nginx active configuration. A rollback that cannot be validated raises HOLD requiring operator intervention. No automatic signed KH Apply retry, FRPS restart, or lease release.

**Not yet implemented:** post-crash journal/reconciliation, signed action broker, explicit 443 vhost attestation, durable route ownership and request idempotency, verified unmount/cleanup, attack-resistant concurrent helper authorization, 3-way transaction reconciliation (Signed KH Apply + Nginx + lease), or complete installer.

## Next PR contract

- Review IR signed broker envelope, read-only preview and least-privileged local IPC, including binding to exact tunnel+port+path and user/operator authorization.
- Restrict any high-trust route action to the *verified* Signed KH inventory: only enabled VLESS/XHTTP `127.0.0.1` inbounds; refuse absent/invalid schemas.
- Installer creates scoped bridge only after `nginx -t` and exact TLS host scope check; install helper as immutable root-owned executable with approved hash, not `curl | sh`.
- Test on **new** disposable IR/KH snapshots with a third inbound, conflicting location/port, bad signatures, failed reload, reboot/crash recovery, and real external XHTTP clients. Existing `45121` and `49328` remain untouched until explicitly approved live cutover.
