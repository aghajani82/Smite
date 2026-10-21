# Stage 14 — Frozen cross-repository preview contract (not a release)

**Draft only.** Proposed SemVer: `2.0.0-rc.0`, deliberately **not published**,
not tagged, not deployed, and not an upgrade to either VPS.

The last reviewed Smite security branch (draft PR #12) contains the stacked
Panel/Node Pairing, HMAC, admin JWT, signed transports and FRP/Backhaul
changes. The accompanying U-OPTI chain (drafts #28–#35) contains the
gateway/wizard/Compose/source-parity stages. A separate U-OPTI draft #27
was originally created on a sibling branch and would otherwise be missing
from the U-OPTI Stage13 lineage. Stage14 U-OPTI explicitly incorporates
its JWT admin-overlay guard; this preserves the important distinction
between *new security images* and *legacy bind-mounted Python sources*.

`release/stage14-review-contract.json` names the proposed version, signed
targets, mode switches, expected PR chains and explicit release blockers.
`tests/test_stage14_review_contract.py` verifies the manifest, identical
Panel/Node HMAC primitives, request-byte interoperability, replay/tamper
rejection, default-disabled security modes, and critical router integration.

The U-OPTI Stage14 partner branch pins this review source to an **exact
40-hex commit**, rather than floating `main` or `latest`, and tests U-OPTI's
gateway request against Smite's actual Node HMAC verifier in GitHub Actions.

**These checks prove source consistency, NOT production readiness.**

Release HOLD remains:
- Full review and merging of stacked, currently draft PRs in dependency order,
  with sibling/overlay reconciliation (and approval of integration diffs)
- A reproducible, reviewed Panel+Node image build, published immutable GHCR
  digests, provenance/attestation and installer digest pin update
- Tested pairing ingress that overwrites the untrusted client header,
  ratelimits issuance/redemption, and enforces TLS/443 certificate trust
- Real service UID/GID permission checks for 0600 secrets and persistent
  replay SQLite and Panel Fernet master backup
- Nginx/443 exact HMAC target preservation for **both** directions, source
  ACLs and hostname/SNI validation with real request tests
- Explicit snapshot verification and restore rehearsal on the two disposable
  VPS servers; signed registration, apply/remove, update/reapply and actual
  FRP/Backhaul/XHTTP client traffic after restart
- Review of Private Network mode separately; do not silently change modes.

Do not treat source CI SUCCESS or proposal `2.0.0-rc.0` as permission
to build a production image, merge, release, activate signed mode or alter
FRP/Backhaul on IR/KH.
