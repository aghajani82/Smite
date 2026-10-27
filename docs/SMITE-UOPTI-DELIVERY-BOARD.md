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
| **Open PRs after integration** | U-OPTI **0**, Smite **0**: historical Smite #20 and #32 closed after source-equivalent main PR #37 merged and CI passed |
| Smite M1b | **Merged #35** at `237c914792903e334859a025500a3b0a5a86960d`: independent XHTTP route planner and canonical broker HMAC intent issuer, their tests and one CI workflow, **8/8 checks PASS** |
| Smite M2–M4 source | **Merged PR #37** at `bbc057917d5a7e9b5f725a38923e9d8cc3432a84`, **19/19 CI PASS**: exact existing FRPS, Signed KH Sanaei, Panel XHTTP UI, Node broker, Nginx host transaction code blobs; no new feature scope | 
| Runtime consequences | **NONE**: GitHub source/CI integration only. Existing IR/KH Docker images, Nginx, FRP, Pairing, routes, credentials and Grandoptical unchanged |

### Remaining puzzle pieces — NO NEW FEATURES

| Order | Existing source | What is still missing | Safe promotion gate |
| --- | --- | --- | --- |
| **M2 / Pairing** | Smite main #34 signed-only admin reservations; U-OPTI main pairing wizard/strict runtime | A **matching, independently verified Panel+Node image pair**, HTTPS/443 ingress and replay/identity migration proof on disposable IR, then true signed check-in and Panel→Node verified status | Main source is merged; hold live activation until exact digest/rollback checks pass |
| **M3 / KH inventory** | Signed KH inventory, read-only Compose mount and Panel selection **integrated into main #37** | Verify actual KH database path, read-only permission, schema and secure pairing after new image build | Real disposable KH tests; unsupported/missing Sanaei must remain safely unavailable |
| **M4a / FRP multiport** | Shared FRPS owner, durable `FrpProxyLease`, status proof, Node protection and UI **integrated into main #37** | Pair IR/KH Node, test one owner with multiple child inbounds; reboot/rollback/collision negative cases | Signed managed mode only; no second FRPS and no automatic owner reapply |
| **M4b / XHTTP orchestration** | Smite main #35 planner+issuer, main #37 Signed Node→Broker forwarder and Panel lifecycle/UI, U-OPTI main root Broker + grant provisioning | Test live TrustedGrant approval, vhost-owned Nginx bridge, single apply, rollback and unknown-route rejection | Operator-approved root grant only; no server mutation automatically from source merge |
| **M5–M6 / final** | Prior two-inbound field trial documented on an **older, distinct** RC4/RC5 IR/KH setup | Fresh Clean-RC real client, restart, disconnect, rollback, snapshot and full two-host rebuild | Only real client success and successful recovery qualifies final release |

**Resolved:** Smite #20 and #32 have been superseded by the **clean main-based #37** source integration. The 45 copied Git blobs are source-identical to the reviewed #32 head; old pairing, RC tag-only workflow changes and historical docs were deliberately not copied. PR histories remain available without separately merging the obsolete parent chain. **Next step is build and test, not more speculative source work.**

**Source of truth:** this board is the only active milestone list. Keep U-OPTI Issue #47 as historical audit/handoff pointer; do not create new staged PR chains or redundant work trackers. Old #20/#32 are closed after verified source promotion; use main #37 and immutable paired images for lab tests. Branch deletion and live server changes are intentionally out of scope.

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
| M3 | KH Node install, approved origin, signed pairing and least-privilege Sanaei metadata | **SOURCE/CI PASS; main PR #37** | **NOT DEPLOYED / PENDING** | Build matching images; test signed KH pairing and read-only Sanaei inventory without client secrets |
| M4 | One shared FRPS owner, explicit additional XHTTP ports; signed route intent → U-OPTI Broker → Nginx | **SOURCE/CI PASS; main PR #37 (19/19 checks)** | **NOT DEPLOYED / PENDING** | Test Signed Owner, active lease, KH inventory, root TrustedGrant, atomic Nginx and rollback on disposable IR/KH |
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
- Smite **PR #37**: 45 selected FRPS/XHTTP/Sanaei/Broker runtime and test files integrated to main at `bbc057917d5a7e9b5f725a38923e9d8cc3432a84`, **19/19 checks PASS**; this is source-only. Smite **#20/#32** were closed as superseded without replaying their historic parent chains.
- U-OPTI **PR #56**: Clean-RC IR interrupted-install recovery integrated in main.
- U-OPTI **PR #57**: docs aligned to this board and broken/stale recovery/wizard CI assertions repaired; merged into U-OPTI **main** at `cb72d42af7bc78e18152588bdc8562d96b454f07`, 16/16 CI checks successful. No installer code was changed.

**Status update discipline:** update this board with evidence (SHA + CI + field output) when each milestone changes. Never report an unrun field test as PASS.
