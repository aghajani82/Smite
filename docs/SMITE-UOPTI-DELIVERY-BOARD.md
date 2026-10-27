# Smite × U-OPTI — single delivery board

**Updated:** 2026-10-27. **Scope:** disposable IR/KH lab VPS only. Production Grandoptical is **out of scope**.

This file is the canonical **delivery-status board** for the Smite repository. Every completed milestone must have (1) a reviewed source SHA, (2) green security/CI gates, (3) a documented rollback, and (4) applicable real two-host field evidence. **Merged to `main` does not imply field-qualified or production-ready.** U-OPTI installation scripts and pinned local/offline images have independent versions and must be validated together.

## GitHub puzzle consolidation — verified 2026-10-27

**No source or history was deleted.** Closing a draft PR means its ticket is no longer actionable; GitHub retains its commits, comments, tags and branch. Old completion claims remain field-qualified only where stated.

| Inventory | Audit outcome |
| --- | --- |
| Smite historical stacked PRs **#2–#15** | **CLOSED** as superseded: #15 is an ancestor of main via merged #16; no individual re-merge required |
| Smite old #17 pairing PR | **CLOSED**: its candidate verifier file matches main Git blob; updated signed-only reservation is main PR #34, so older legacy fallback must not return |
| Smite #23 one-shot RC5 tag gate | **CLOSED** as obsolete: tag `v2.0.0-rc.5` already exists and peels to reviewed commit `be00b20d64051f5bbd5597701ebdbe60b33b481c` |
| U-OPTI historical stacked PRs **#29–#46** | **CLOSED** as superseded: #46 is a Git ancestor of main via merged #48 |
| U-OPTI parallel #27 JWT overlay | **CLOSED**: critical helper/test blobs are identical in main and the packaging/wiring was integrated in #48 |
| **Open PRs** | U-OPTI **0**, Smite **2**, both still genuinely unique: #20 and #32 |
| Smite M1b | **Merged #35** at `237c914792903e334859a025500a3b0a5a86960d`: independent XHTTP route planner and canonical broker HMAC intent issuer, their tests and one CI workflow, **8/8 checks PASS** |
| Runtime consequences | **NONE**: this GitHub audit did not change local IR/KH images, Docker, Nginx, FRP, Pairing, routes, credentials or Grandoptical |

### Remaining puzzle pieces — NO NEW FEATURES

| Order | Existing source | What is still missing | Safe promotion gate |
| --- | --- | --- | --- |
| **M2 / Pairing** | Smite main #34 signed-only admin reservations; U-OPTI main pairing wizard/strict runtime | A **matching, independently verified Panel+Node image pair**, HTTPS/443 ingress and replay/identity migration proof on disposable IR, then true signed check-in and Panel→Node verified status | Main source is merged; hold live activation until exact digest/rollback checks pass |
| **M3 / KH inventory** | Signed read-only KH parser/API already in Smite #20; missing Compose read-only mount and further orchestration in **draft #32** | Review exact KH DB bind and schema access with no client secrets, approved origin/Pairing and safe no-Sanaei fallback | Extract only inventory/mount/API/testing set, CI-green against current main before promoting; do not wholesale merge #32 |
| **M4a / FRP multiport** | **Draft #20**, shared FRPS owner, signed listener proof, durable `FrpProxyLease`, owner/child UI and tests | Current main-based integration, negative/concurrency/reboot tests and disposable paired-Node verification | Promote tightly scoped feature-flagged FRPS package with verified full CI; retain single FRPS control listener |
| **M4b / XHTTP orchestration** | Smite main #35 pure planner+issuer; Smite #20 signed forwarder and isolated Nginx transaction prototype; **draft #32** Panel UI lifecycle; U-OPTI main root Broker and grant provisioning | Signed KH inventory→verified lease/owner→root TrustedGrant→Nginx-owned bridge/rollback, including no duplicate apply | Integrate in that dependency order only; host mutations OFF without explicit root grant, CI and field negative/rollback checks |
| **M5–M6 / final** | Prior two-inbound field trial documented on an **older, distinct** RC4/RC5 IR/KH setup | Fresh Clean-RC real client, restart, disconnect, rollback, snapshot and full two-host rebuild | Only real client success and successful recovery qualifies final release |

**Explicit exclusion:** Smite #20 (134 historical feature-branch commits, not 134 features) must not be merged wholesale into main. Some of its files already match main (including #34); promote only **actual remaining changed files** in coherent dependency packages. Smite #32 builds on #20 and must not be merged directly into main with implicit parent scope.

**Source of truth:** this board is the only active milestone list. Keep U-OPTI Issue #47 as historical audit/handoff pointer; do not create new staged PR chains or redundant work trackers. Close remaining #20/#32 **only after** the unique code lands in main via reviewed, CI-passing scoped PRs. Branch deletion and live server changes are intentionally out of scope.

## Current laboratory state (operator audit, 2026-10-27)

| Component | Evidence / state |
| --- | --- |
| IR Panel container | Running; image label `smite-panel:stage15-local` |
| IR Node container | Running; image label `smite-node:stage15-local` |
| Panel configuration | `SMITE_VERSION=2.0.0-rc.1`, signed registration and signed Panel→Agent mode |
| Node configuration | `SMITE_VERSION=2.0.0-rc.1`, Panel auth **paused**, Agent auth **strict** |
| Pairing menu status | `PANEL_PAIRING=NOT_ENABLED`, `CREDENTIALS=NOT_STAGED`, `REPLAY_ENROLLMENT=NOT_PROVISIONED` |
| IR local U-OPTI Broker | Previously attested ready, Node socket forwarding verified; **no TrustedGrant** |
| Node visible in Panel | **NO**. A running Docker container is not a paired/registered Node |
| KH paired node, FRP/XHTTP, live client | **NOT YET VALIDATED in this Clean-RC installation** |

No pairing code, key, token, UUID or admin credential belongs in a report, GitHub issue or CI log. Never infer that a container image's name identifies its source digest; verify the exact image/source manifest first.

## Milestone order and status

| ID | Milestone | Code / CI | Lab/field | Next action |
| --- | --- | --- | --- | --- |
| M0 | Clean-RC IR Panel + Node, admin account and local Broker | U-OPTI clean recovery path integrated | **Partial PASS**: containers/Broker; pairing paused | Keep state intact; read-only audits first |
| M1 | Signed-only, role-bound IR/KH Node reservation in Panel UI | **SOURCE/CI PASS; merged into Smite main** via PR #34 (merge `cc6e74daae0cacbff0b896221304c95b0a41bb28`) | **NOT DEPLOYED** | Rebuild/reverify paired Panel+Node candidate images; do not assume source merge upgrades RC1 Docker images |
| M1b | Offline XHTTP route planner + canonical broker HMAC intent issuer | **8/8 CI PASS, merged into Smite main** via PR #35 (`237c914792903e334859a025500a3b0a5a86960d`) | **Source-only; no runtime hook** | Integrate exclusively through separately reviewed Signed Node/Broker/TrustedGrant flow in M4 |
| M2 | IR one-time admin-approved HTTPS/443 pairing, durable replay and signed check-in | Existing U-OPTI wizard `u-opti --smite-pairing` and signed Smite endpoints; default OFF | **PENDING** | Confirm candidate source SHA/image provenance, gateway ingress, schema, backup, secret mounts, signed both-way proofs and rollback; then opt-in field pairing |
| M3 | KH Node install, approved origin, signed pairing and least-privilege Sanaei metadata | KH inventory read-only mount remains separate draft **PR #32** | **PENDING** | Review and integrate the read-only mount separately; never export client credentials |
| M4 | One shared FRPS owner, explicit additional XHTTP ports; signed route intent → U-OPTI Broker → Nginx | In RC2 development branch; requires TrustedGrant and discrete end-to-end gates | **PENDING** | Test no duplicate FRPS, scope grant, atomic route and rollback on lab IR/KH |
| M5 | New client VLESS/XHTTP over IR HTTPS/443 to KH Sanaei | Not yet end-to-end verified | **PENDING** | Use a **new** inbound; confirm real client + recoverability without touching working services |
| M6 | Repeatable two-VPS clean rebuild, upgrade, rollback and final release | No final stable release authorization | **PENDING** | Only after full fresh-install acceptance, publish source/image pair; promote tested components to main |

## Integration rules

1. Promote **scoped, reviewed, CI-passing** change sets to `main` through PRs. Prefer a small independently testable PR over merging the full multi-feature RC2 branch.
2. Do not call `main` a stable deployable release until M2–M6 field checks pass. Branch merges and tagged/image releases are separate operations.
3. All security defaults remain **fail closed**: signed mode never falls back to legacy IP/port registration, an unpaired Node remains pending, and Broker cannot create a live route without an explicit TrustedGrant.
4. Keep initial U-OPTI wizard flow simple: IR install → KH install → separate control-plane pairing → choose inbound/port → activate reviewed route. Operator controls must stay in the Panel; terminal actions are installation/recovery-only.
5. Before changing a VPS, verify mounted files and pinned image SHA, back up configs/SQLite/identities/replay state, and have a tested narrow rollback. Do **not** change `grandoptical.ir` or its live tenants.
6. Old stacked/Draft PRs are **historical evidence**, not pending instructions. Close only those proven superseded; avoid bulk merges or deletion of their unique changes.

## Important GitHub references

- Smite **PR #33**: role-bound signed Iran/KH reservation and fail-closed UI (merged into RC2 integration branch); **PR #34** promoted those exact seven reviewed files plus this board to **main**, 11/11 CI checks successful.
- Smite **PR #17**: older overlapping pairing draft; must not be merged directly into main.
- Smite **PR #20**: multiport/FRPS integration draft (field-wide gate not complete).
- Smite **PR #32**: separate KH Sanaei read-only inventory draft.
- U-OPTI **PR #56**: Clean-RC IR interrupted-install recovery integrated in main.
- U-OPTI **PR #57**: docs aligned to this board and broken/stale recovery/wizard CI assertions repaired; merged into U-OPTI **main** at `cb72d42af7bc78e18152588bdc8562d96b454f07`, 16/16 CI checks successful. No installer code was changed.

**Status update discipline:** update this board with evidence (SHA + CI + field output) when each milestone changes. Never report an unrun field test as PASS.
