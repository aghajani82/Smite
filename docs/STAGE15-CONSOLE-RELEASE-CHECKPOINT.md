# Console-only release checkpoint — 2026-11-01

## Binding product decision

Passkey and independent Secure Web Approval were rejected by the operator.
The sole approved flow is: configure Sanaei KH inbound with the intended port
and path; create the FRP child in Smite; request XHTTP publication in Panel;
review on authenticated IR terminal using Smite Management G, then 1; return
to the same Panel dialog and explicitly submit a fresh final publication request.
Verify checks the signed FRPS listener; real VLESS/XHTTP traffic remains a separate test.
No automated approval, browser popup or alternate approval domain belongs in this release.

## Selected source, not a wholesale experimental PR merge

U-OPTI foundation: PR #73 `9370fcd4b44859eff7d4cb6924c3905b771a5885`.
Smite foundation: PR #40 `50eb4f174eef67049eff82dad194e762181f18ca`.
Selected U-OPTI console/menu changes from #74 `76ae65207e613c74c7b4a65fd96225ff8d6caff9`.
Selected Smite operator UI from #41 `3969855298ce7e63ea8a3f7824a0ae20aea09b2c`.

Both selected branches target main and retain the reviewed Stage15 foundation.
They do not include the experimental branch's approval services, Passkey labs,
Node attestation additions, broker web-marker/queue hook, or preview image tools.
Smite also removes the optional browser approval code rather than only hiding it
behind an empty build-time origin. Console-only policy tests reject reintroduction.
U-OPTI keeps the existing broker from #73 and adds G/1, role navigation and guards
against legacy image upgrade/rollback on existing FRP/WSS state.
Old experimental branches and historical releases are preserved for provenance;
they are not candidates for default installation.

## Completed checkpoint

- Separate local worktrees and release/stage15-console-only-20261101 branches.
- Selected console flow, manual publication, Verify feedback and compact sidebar.
- Local frontend typecheck/build and seven UI contract tests passed.
- Local root review (14), broker (30), nonce ledger (10), signed intent (9),
  KH inventory (16), guided roles (6) and existing menu regressions passed.
- New policy tests: three U-OPTI and two Smite checks passed.
- No live host action, restart, main merge, tag move, version bump, stable
  publication, old PR closure, artifact deletion or branch deletion.

## Remaining gates — do not label this ready to publish

1. Observe CI on the exact two selected release branch HEADs and fix any failure.
2. Finish the first-install wizard; existing guided screens are safe navigation
   and some signed/application states remain HOLD. Do not turn process presence
   into signed approval. Existing G validator remains the authority.
3. Prepare exact selected Panel/Node images, manifest and signature verification.
   Current stable installer still points to upstream Smite 0.1.7. Do not point it
   at an unbuilt/unverified candidate, mutable tag or experimental preview pair.
4. Qualify fresh IR-first and KH-first install, pairing, inventory, owner/child,
   G/fresh publication, reboot preservation and rollback on disposable fixtures.
   Existing active-host migration is separate; never use the no-child upgrader.
5. Inventory remaining GHCR packages and transient artifacts, expiration and all
   references. Only propose deletion after proving unused and retaining rollback.
6. Finalize versioning and release trigger review. U-OPTI main changes to VERSION,
   CHANGELOG.md or release.yml can publish automatically. Merge and stable release
   require explicit final operator approval of exact commits and effects.
7. After approved merge/release, reconcile old Draft PRs and proposed branch cleanup;
   do not close or delete them merely because selected branches now exist.

## Resume protocol

Refresh remote branch HEADs and CI before edits. Continue from the selected
release branches, not #74/#41 wholesale. Record each completed work unit as an
independent commit. Never assume rate-limit reset resumes work automatically;
the operator will send a continuation message. The last pushed commit plus this
file is the recovery point if the interactive session stops.

Preserve Grandoptical, all existing tunnels including the newly successful field
test, FRPS Owner, FRPCs, Signed Pairing, Replay, TrustedGrants and Nginx state.
No new mandatory Backhaul dependency and no automatic public ports.
