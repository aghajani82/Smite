# Smite FRP Singleton Multiport — Field Trial Closeout & Next Milestone

> **Status:** FRP singleton multiport, two XHTTP inbounds, and the operator's real-client tests **PASS** on the disposable IR/KH field-trial hosts. **Automatic** Sanaei inbound discovery and Nginx route provisioning are **NOT implemented/validated** yet.
>
> **Date:** 2026-10-26. **Evidence type:** operator terminal output and explicit real-client success report, combined with reviewed release source. This is an observed field-trial milestone, **not** a claim of a full clean-install or all-user production release.
>
> **Deployment authorization:** NONE. This file documents the successful state only; it does not authorize changes on either VPS or the separate Grandoptical production VPS.

## 1. Immutable source and active components

| Component | Observed field-trial baseline |
|---|---|
| GitHub repo | `aghajani82/Smite` |
| Reviewed RC5 tag | `v2.0.0-rc.5` -> `be00b20d64051f5bbd5597701ebdbe60b33b481c` |
| IR Panel | `v2.0.0-rc.5` (verified running image reference, source-revision label, `/app/VERSION=2.0.0-rc.5`) |
| IR Panel image | `ghcr.io/aghajani82/smite-panel@sha256:e789e69fb6a2dd59fc1d91cced22338af0c21919560e6407014f66885d5125e2` |
| Published RC5 paired Node image | `ghcr.io/aghajani82/smite-node@sha256:6d7da6885ae615195a5403085d6e1427580b6b12678c61061faed3e1678a7e13` — published and verified, **not the field-trial deployed Node version** |
| IR + KH Node runtime | RC4 image retained, healthy as seen in field preflight/cutover; not upgraded to RC5 |
| Previous RC4 Node digest | `ghcr.io/aghajani82/smite-node@sha256:27c280b25072351cfa3d18b63a184ec3086af46c2c95ad079a0c24152123df7d` (verified IR in cutover) |
| Auth/control mode | Signed Agent auth STRICT; Panel SIGNED + MANAGED; durable replay protection |
| Git flow | Keep `main` unchanged pending explicit approval; preserve immutable RC3/RC4/RC5 tags and signed images |

Related changes: PR #22 (fixed Panel signed allowlist for exact `GET /api/agent/frp/owners`), feature PR #20 (FRPS singleton multiport, open), RC5 gate PR #23 (open, not merged). The RC5 release was independently verified for signed image digests, source revision and paired manifest.

**Do not equate published RC5 Node images with live RC5 Node deployment.** This field test deliberately preserved RC4 Nodes while upgrading the IR Panel to RC5.

## 2. Field-proven data path

```text
Real VLESS/XHTTP client
  -> approved IR domain, HTTPS/TLS :443
  -> IR Nginx route (exact + prefix; path preserved)
  -> IR 127.0.0.1:<inbound-port>
  -> ONE existing frps instance
       control 127.0.0.1:7000
       proxy listeners 127.0.0.1:45121 and 127.0.0.1:49328
  -> WSS/443 signed-managed FRP pairing path to KH
  -> TWO separate frpc processes on KH
  -> KH 127.0.0.1:<inbound-port>, Sanaei 3x-ui Xray
```

| Tunnel role | IR FRPS remote port | KH XHTTP inbound port | KH exact XHTTP path | Observed outcome |
|---|---:|---:|---|---|
| Existing FRPS owner `trial-frp-45121` | 45121 | 45121 | `/45121/www` | Active; signed proof; Nginx route; **real client connected** |
| Shared child `trial-frp-49328` | 49328 | 49328 | `/49328/sso` | Active; durable unique lease; signed proof; Nginx route; **real client connected** |

Both KH Xray inbounds were read from the local 3x-ui DB using read-only SQLite inspection and were enabled/bound to `127.0.0.1`; network `xhttp`, protocol `vless`. No UUIDs, tokens or credentials are recorded here.

**IR host proof:** `ss -Hlntp` showed exactly one listener for each of `127.0.0.1:7000`, `127.0.0.1:45121` and `127.0.0.1:49328`, all owned by **one frps process** (then host PID 561045; process IDs are ephemeral). Inside IR Node, `psutil` confirmed the same PID for all three ports. Signed `GET /api/agent/frp/owners` independently returned one owner with both proxy ports. In the Panel, the owner and child were two FRP DB rows; the child was **Active** and had exactly one durable lease for port 49328.

**KH proof:** `docker top smite-node` reported two `frpc` processes; `ss` showed both Xray loopback inbounds listening; Node health was `healthy`.

**Nginx proof:** `nginx -t` and reload **PASS**, original `45121` location content remained unchanged, IR frps PID unchanged, and new path rules were added for **both** `/49328/sso` and `/49328/sso/` to `127.0.0.1:49328` with path-preserving proxy. The deployed file is `/etc/nginx/u-opti-smite-frp-xhttp.conf`. It is U-OPTI-owned existing infrastructure; automatic Smite management must establish an approved ownership/include boundary first.

**End-to-end proof:** operator explicitly confirmed both real clients were connected and working after the final Nginx route change. This assertion applies to these **two** field-trial inbounds, not any new inbound created in the future.

## 3. Resolved defects and cautions

- RC4 Panel signed request builder rejected exact `/api/agent/frp/owners` before HTTP dispatch. PR #22 added a single GET-only, query-free, payload-free allowed target and fail-closed regression tests; RC5 Panel resolved the issue.
- Shared-child create performed **one** signed KH Apply, then got live signed IR owner proof. The child row, unique lease and Active status were observed; **do not re-run Apply** on an ambiguous/failure status. A late host-side script showed `HOLD` despite subsequent direct host socket audit and signed owner proof PASS. Diagnostics should use exact `ss` local address columns and cross-check one FRPS PID instead of brittle raw-line regex matching.
- The old operator-level creation workflow cannot automatically configure Nginx when a new KH inbound appears. The `49328` path was added using an operator-run, backup-first, `nginx -t`-gated script. The **next inbound still requires manual routing** until the follow-up work is implemented.
- The generic Edit Tunnel UI still exposes owner-only fields (FRPS token and control/bind port) even on shared children. **Backend** RC5 `PUT /api/tunnels/{id}` already rejects shared-child spec mutations with 409. Correct the UI so it does not suggest an unsupported or unsafe action.
- Keep current owner/child entries, durable lease and two Nginx paths intact. Don't re-create the working tunnels merely to try the old UI.

## 4. Target operator experience (not yet delivered)

### First-time deployment
1. The operator runs a **release-pinned bootstrap installer** for the IR Panel; select the approved domain/TLS 443. IR signed Node is bootstrapped/enrolled, with explicit verification.
2. A one-time **KH signed Node** installation/enrollment is still required (either a short KH bootstrap command or a separately designed, authorized secure provisioner). **Installing a Panel on IR alone cannot silently install software on KH.** KH Sanaei/3x-ui is an optional independently installed app that provides Xray inbounds; Smite must not assume its presence.
3. Panel menu: **Tunnels → FRP → Select IR/KH pair → select or initialize first FRPS owner**. Existing owner => **Add inbound/port**; no second FRPS or IR owner reapply. FRP remains independent from Backhaul and other tunnel cores.
4. For each new Sanaei VLESS/XHTTP inbound, Smite reads the approved KH inbound's **actual port and exact path**, validates loopback binding, creates one signed-managed child proxy/lease, registers its approved Nginx route on IR, verifies the signed FRPS port and Nginx listener/routing, and reports **Ready for client test**. Only a real client test may be labeled end-to-end PASS.
5. Basic UI has at most the few meaningful choices; sensitive expert settings remain collapsed. No copy-paste token or Nginx shell editing is part of the routine Add Inbound flow.

This is the *future product contract*, not a current claim. The existing `scripts/install.sh` is legacy and presently clones an upstream repository; it **must not be advertised as the production-grade pin-by-digest one-click installer** until reviewed and fixed.

### Required safety contract
- **One public 443 gateway**, with any intentionally public SSH managed separately; all FRPS proxy/bind services and Xray inbounds remain loopback. No direct public 7000, 45121 or 49328.
- Signed-only Panel-to-Node commands with exact-target allowlists; no downgrade to legacy, no token exposure, no arbitrary host/query targeting, no unapproved read of KH Xray databases from IR.
- Read-only, versioned Sanaei inbound inventory through an explicitly approved local KH Node helper, revealing only port/path/network/enabled/listen and no UUIDs or secrets; fail closed if 3x-ui DB schema/version/permissions are unsupported. Safe explicit manual port+path fallback.
- Exact and prefix XHTTP locations with path-preserving `proxy_pass`; no wildcard proxy to arbitrary port. Manage an isolated root-owned Nginx include **only after** U-OPTI/Smite boundary is approved. Refuse duplicates, prefix collisions, mismatched paths, unhealthy owner/engine and non-loopback destinations.
- Back up config, atomic staged update, `nginx -t`, guarded reload, and scoped rollback for new route ONLY. Owner FRPS and existing `45121` config must never be modified by a child route.
- Reconcile split-brain safely: an ambiguous signed KH Apply leaves a durable lease and pending/error child for manual review; no automatic duplicate POST. Signed KH remove + signed IR absence before releasing lease; route cleanup constrained to owned file.
- Deploy/test on disposable snapshots first. No changes to Grandoptical. Explicit operator consent for any live cutover.

## 5. Open work, in implementation order

- [ ] **Bootstrap/release security:** audited release-pinned installer(s), IR/KH enrollment, approved 443 domain/TLS configuration, system-level rollback and reboot test; no unreviewed `git pull`.
- [ ] **KH inbound discovery API:** versioned read-only Sanaei/3x-ui inventory with `network=xhttp`, exact path, port, enabled and loopback listen validation; absent-app and unsupported-schema HOLD.
- [ ] **Smite auto route manager:** per-inbound Nginx snippets/approved include, exact+prefix preservation, idempotence and collision checks, atomic update, backup, validation, reload and scoped rollback.
- [ ] **Orchestrated wizard:** FRP engine selection, first owner vs existing owner, signed pair/engine/proxy proof, lease planning, proxy create and route registration, confirmation and safe reconciliation; FRP independent from Backhaul.
- [ ] **Shared-child Edit screen:** show linked owner and read-only protected control fields; hide token; do not bypass 409 backend spec immutability.
- [ ] **Remove/update reconciliation:** no owner restarts; signed KH removal, signed IR absence, then guarded route cleanup and lease release.
- [ ] **End-to-end acceptance:** disposable fresh IR+KH pair; first, second, third inbounds; non-default XHTTP paths, exact+prefix, duplicates, invalid inputs, failures/reboots, two active clients during Nginx reload, real network client traffic confirmation and no unintended exposure on 7000/proxy ports.
- [ ] **Release and docs:** review + CI + immutable signed Panel/Node pair and matching source manifest; operator documentation in Persian/English; explicit `main` merge approval.

**Checkpoint guidance:** close the *field-trial infrastructure milestone* but leave the **automatic Add Inbound / Route Sync milestone OPEN**. Future implementation should be in independent feature branches and PRs, not by mutating immutable RC5.

## 5A. Development progress after field closeout (2026-10-26)

These are **reviewed source changes on the feature branch, not upgrades to the live IR/KH pair**. The immutable signed RC5 release still contains the older code.

| Workstream | GitHub changes / CI | Implementation status | Deployment status |
|---|---|---|---|
| Shared FRPS child Edit form | [PR #25](https://github.com/aghajani82/Smite/pull/25) merged; 4/4 workflows PASS | Child name-only edit; owner, Bind Port, FRPS Token and child port read-only/protected; existing server-side 409 guard retained | Not published/deployed |
| KH Sanaei VLESS/XHTTP discovery | [PR #26](https://github.com/aghajani82/Smite/pull/26) merged; 10/10 workflows PASS | KH-only strict signed GET `/api/agent/inbounds/xhttp`, SQLite parser validates enabled XHTTP loopback inbounds and returns only sanitized port/path/network facts | Default OFF; approved read-only DB mount and new signed Node image still required |
| IR Nginx automatic XHTTP route | [PR #27](https://github.com/aghajani82/Smite/pull/27) merged; 3/3 workflows PASS | Pure exact+prefix location **planner**, path-preserving loopback upstream, route collision and invalid input tests | **Not automatic yet**; no privileged host writer, `nginx -t`/reload orchestration or lifecycle API yet |
| Simple IR/KH install and enrollment | Not implemented in this milestone | Clean installer needs release-pinned Panel/Node, explicit roles, scoped enrollment, verified 443 and safe Nginx helper deployment | Not deployed |

### Next implementation boundary

1. **Local helper prototype added in PR #29:** fixed-path root-only scoped route creation, preflight, atomic new-file install, `nginx -t`, guarded reload, rollback of the new file, collision tests and FRPS PID checks passed mocked offline CI. **Still needed:** approved TLS/443 bridge installer and vhost-scope attestation, signed/bound IPC broker, crash journal/reconciliation, host E2E tests and release deployment. Never grant broad filesystem privileges to a Panel container or modify U-OPTI-owned `/45121/www`.
2. Deliver an audited **read-only** KH 3x-ui DB mount/provider install gate (the KH Node sees only the explicitly approved source), and wire the signed inventory through the Panel FRP wizard.
3. Wire signed child Apply + route registration with reconciliation for ambiguous POST, unique durable lease and verified owner; never retry automatically or restart the singleton FRPS.
4. Implement the release-pinned role-based IR Panel / IR Node / KH Node bootstrap installer, with independent FRP/Backhaul selection, one public TLS 443 gateway and no automatic global Git pull.
5. Run CI/security/E2E on newly built disposable VPS snapshots using **three inbounds**, boot/restart survival and two simultaneous real clients; only then publish separately signed source-matched images and request explicit permission for live cutover.

**Host-side transaction reference:** [PR #29](https://github.com/aghajani82/Smite/pull/29) and [security boundary design](SMITE-XHTTP-HOST-ROUTE-TRANSACTION-DESIGN.md). This is NOT installed, not connected to Smite Panel, and not ready for production auto-routing.

**Persian operator status:** فرم Edit در کد اصلاح شده؛ شناسایی امضاشده اینباند سنایی و طرح‌ریز مسیر Nginx هم به کد اضافه شده‌اند. اما نصب روی سرورهای فعلی، اتصال خودکار به Nginx و ویزارد نصب نهایی هنوز انجام نشده‌اند. تا آماده‌شدن این موارد، دو تانل فعلی را بدون تغییر نگه دارید.

## 6. References

- [FRPS multiport feature PR #20](https://github.com/aghajani82/Smite/pull/20)
- [Signed owner proof fix PR #22](https://github.com/aghajani82/Smite/pull/22)
- [RC5 tag-gate PR #23](https://github.com/aghajani82/Smite/pull/23)
- [Immutable RC5 tag](https://github.com/aghajani82/Smite/releases/tag/v2.0.0-rc.5)
- [RC5 independently verified release workflow](https://github.com/aghajani82/Smite/actions/runs/40231027648)

## 7. خلاصه فارسی برای اپراتور

**بخش انجام‌شده:** هر دو کانفیگ XHTTP روی پورت‌های 45121 و 49328 با یک FRPS روی ایران، دو FRPC روی خارج، کنترل Signed و Nginx پشت HTTPS/443 تست واقعی موفق داشتند.

**بخش باقی‌مانده:** نصب اولیه امن و ساده Panel/Node، شناسایی خودکار پورت و مسیر XHTTP از سنایی، اضافه/حذف خودکار مسیر Nginx و ساده‌سازی فرم ویرایش تانل فرزند. در وضعیت فعلی هنوز برای هر اینباند جدید به تنظیم کنترل‌شده مسیر Nginx نیاز داریم.

**قانون قطعی:** اصلی‌ترین FRPS و تانل‌های سالم را دوباره نصب نکنیم، شاخه main و Grandoptical را تغییر ندهیم و بدون اجازه انتشار یا Deploy انجام ندهیم.
