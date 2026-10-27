# Smite × U-OPTI — single delivery board

**Updated:** 2026-10-27. **Scope:** disposable IR/KH lab VPS only. Production Grandoptical is **out of scope**.

This file is the canonical **delivery-status board** for the Smite repository. Every completed milestone must have (1) a reviewed source SHA, (2) green security/CI gates, (3) a documented rollback, and (4) applicable real two-host field evidence. **Merged to `main` does not imply field-qualified or production-ready.** U-OPTI installation scripts and pinned local/offline images have independent versions and must be validated together.

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
| M1 | Signed-only, role-bound IR/KH Node reservation in Panel UI | Reviewed as Smite **PR #33** on integration branch; isolated promotion to main | **NOT DEPLOYED** | Rebuild/reverify paired Panel+Node candidate images, not a source-only UI edit |
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

- Smite **PR #33**: role-bound signed Iran/KH reservation and fail-closed UI (merged into the RC2 integration branch).
- Smite **PR #17**: older overlapping pairing draft; must not be merged directly into main.
- Smite **PR #20**: multiport/FRPS integration draft (field-wide gate not complete).
- Smite **PR #32**: separate KH Sanaei read-only inventory draft.
- U-OPTI **PR #56**: Clean-RC IR interrupted-install recovery integrated in main.

**Status update discipline:** update this board with evidence (SHA + CI + field output) when each milestone changes. Never report an unrun field test as PASS.
