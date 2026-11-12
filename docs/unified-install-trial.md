# Unified installation trial: Foreign installation grants

Branch: trial/unified-smite-install. Status: store, default-OFF HTTP adapters and gated origin/DNS transport implemented; not a host-installable release.
User approved trial branches only. Never merge main until Mohammad tests and approves.
U-OPTI tracking: https://github.com/aghajani82/u-opti/blob/trial/unified-smite-install/docs/UNIFIED_SMITE_INSTALL_TRIAL.md
Base: 5e7a289071e446345ac27e4255994daf3446430a.

## Implemented checkpoint (2026-11-12)
`panel/app/foreign_install_grants.py` implements an explicitly migrated SQLite
store. The next checkpoint below adds gated HTTP adapters; startup migration and
trusted-origin integration remain disabled.
Existing RC7 pairing codes still have their existing maximum 900-second TTL.
The new grant defaults to 7200 seconds (accepted range 60..7200), a separate
256-bit `smi1_` bearer code hashed at rest, and an exact existing pending Foreign
Node UUID/name/domain binding. Name/role are rechecked at redemption.
A restricted `/smite-node/<32 lowercase hex>` control path is generated at issue.
Reissuing for the same pending name/domain preserves the path, invalidates prior
install grants and unspent legacy pairing codes, and never rotates a paired key.
A valid grant does not itself authorize anonymous reservation or arbitrary URLs.

The client must generate and fsync a random 256-bit hex Node secret in its root-only
identity staging directory BEFORE sending redemption. Over verified TLS it sends
that same secret, exact node name/UUID/control URL and grant code. The database
atomically commits the encrypted identity, exact origin and grant consumption.
The reply contains acknowledgement only, never a server-generated secret.
An identical retry before expiry is acknowledged, including after signed check-in; a different secret is rejected.
After expiry, a successfully paired key remains valid. A client with a lost reply
must use a signed verification path to discover prior success after expiry; that
client flow is NOT implemented yet. Revocation of an identity blocks retries.
Concurrent contenders cannot replace the first committed identity. Issuance cannot
replace any existing identity, including revoked identities.

## Boundaries / remaining integration
- Store functions are not authentication endpoints. HTTP adapters MUST enforce
  current administrator JWT/MFA policy for issue/revoke and trusted TLS ingress
  for redemption, generic errors and no-store headers. Do not log request secrets.
- Domain syntax checks alone are NOT SSRF protection. Network adapters must reuse
  reviewed public-IP DNS pinning, redirect rejection and certificate verification.
  No network request is made by this module.
- The new origin table is gated by a separate default-OFF trust flag, ensuring no
  silent fallback/override of an existing file-approved node. A consumed grant and
  an unrevoked identity must agree before any outgoing signed request.
- Existing private approved-origins file stays read-only. Do not make it writable
  by a generic API. New origin trust must only come from authenticated grant issue.
- Wire reserve + domain + issue in admin UI; obtain the code once before KH install.
- Extend snapshot/revocation evidence for new grant/origin tables. Define rollback:
  disable new grant issuance; keep paired identities and origin trust until migrated;
  do not silently downgrade a database-enrolled Node to legacy transport.
- Explicit schema migration only; feature stays OFF until schema and trusted ingress
  are ready. Do not enable by importing this module or on ordinary application boot.
- Build signed trial Panel/Node images, pin exact digests in U-OPTI, then implement
  the client and full installer orchestration. No install command released yet.

## Verification
19 isolated tests passed: default expiry, secret redaction/encryption, lost reply,
expiry before/after redemption, reissue/path preservation, domain replacement,
revocation, exact scopes, role/name drift, legacy collision, transactional rollback,
concurrent different-key redemption and identical retries, explicit migration.
Existing pairing store: 17 tests passed. Recovery snapshot admission: 6 passed.
The existing Node Pairing Atomic Store workflow now runs these on the trial branch.
Full application integration, HTTP/UI and real two-host tests remain outstanding.

## HTTP checkpoint (2026-11-12)
Added /api/foreign-install/capabilities, /issue, /revoke and /redeem, mounted
in the trial Panel with SMITE_FOREIGN_INSTALL_ENABLED=false by default.
Issuance, revocation and capability checks use the existing real admin JWT,
auth-version and MFA dependency. Redemption requires signed mode, explicitly
migrated schema, pairing master key and the existing trusted gateway ingress
proof as well as a valid scoped grant. No schema creation in HTTP requests.
The route limits streamed bodies to 8192 bytes, rejects unknown fields and
wrong TTL types, marks responses no-store, and hides validation inputs and
internal SQL errors so keys/codes are not reflected. Redemption acknowledges
only the Node ID; it never returns a secret. Pending-code revocation does not
revoke an already enrolled Node.

Local verification: 13 new ASGI/real-JWT tests, 9 existing pairing HTTP tests,
3 real MFA tests, 19 grant-store tests all PASS (44 tests). Existing CI extended
with a separate HTTP job using pinned Panel dependencies. Remote CI must be
checked on the final commit. No server, image publication, or main change.

Important newly verified dependency: signed_agent_transport.py validates TLS,
rejects redirects and ignores environment proxies, but uses httpx hostname DNS
resolution without public-IP pinning. Do NOT assume DNS-rebinding protection
already exists. Add/test a transport that pins vetted public DNS addresses while
preserving certificate hostname/SNI before enabling database-origin trust.

## Next action
The gated origin/DNS checkpoint below is implemented. Continue with admin UI, durable client identity staging, signed lost-reply verification,
snapshot/recovery coverage, signed trial images and U-OPTI orchestration.
Do not enable the new flag or advertise a host install command at this checkpoint.
The external Nginx endpoint/ingress configuration is not wired yet.


## Origin and DNS transport checkpoint (2026-11-12)
SMITE_FOREIGN_INSTALL_ORIGIN_TRUST_ENABLED=false is separate from grant issuance.
With explicit migration and trust enabled, a read-only SQLite snapshot verifies
consumed grant, exact UUID/name/origin/control binding, consumption timestamps,
current Node role/name and unrevoked Foreign identity. Grant expiry after enrollment
is intentionally irrelevant. Missing committed origin evidence, revoked identity,
unsafe/corrupt file or conflicting file/DB approvals fail closed. Matching file/DB
approval still uses DNS pinning. Legacy file-only nodes retain the existing path.
No trusted-origin file is written and no schema is created by lookup.

NodeClient passes database-approved requests through a fresh pinned transport:
resolve once, reject the entire DNS result if any address is non-public/special,
dial one vetted literal IPv4/IPv6 address, retain original Host and TLS SNI/hostname
verification. No redirect, environment proxy, retry or second hostname resolution.
HTTPCore is pinned to 1.0.9 for its tested sni_hostname extension. Reserved and
transition ranges are conservatively denied across Python 3.11/3.12 differences.
Only database-approved Foreign traffic uses this new policy; existing Iran/FRP
and file-approved behavior is preserved.

Rollback contract: stop new issuance with SMITE_FOREIGN_INSTALL_ENABLED=false;
keep origin trust enabled and retain grant/origin/identity rows for enrolled nodes.
Do not disable trust or remove these tables to roll back an active installation:
DB-only nodes will be unavailable. Export/migration and recovery tooling are still
pending; administrators must not manually substitute a file origin to downgrade.
Trust is default-OFF and no installation command enables it at this checkpoint.

Local verification: 20 new tests plus 97 existing tests PASS (117 total). Tests
exercise actual HTTPX/HTTPCore dialing and TLS-context/SNI handling with an offline
network backend, simulated certificate failure before credentials, IPv4/IPv6,
private/mixed DNS, timeout/empty DNS, HMAC bytes, redirect denial, NodeClient routing,
conflict/revocation/missing-evidence failures and legacy behavior. This is not a
public-CA/live-host TLS test. Extended CI runs the same suites; check final commit.

NEXT: administrator UI for reserve/domain/issue and safe code presentation; durable
installer secret staging and signed lost-reply recovery; schema/ingress provisioning
and snapshots/revocation recovery; signed trial images; U-OPTI integrated installer.
Main and live hosts remain untouched. The unified install is NOT ready to run.

## Administrator UI checkpoint (2026-11-12)
The Foreign page now offers a gated installation dialog: name + Gateway domain,
existing authenticated reservation, then a 7200-second grant. Pending rows expose
Installation information for reissue; connected rows do not offer new enrollment.
The default-OFF capability must report both issuance readiness and origin trust,
and the browser must use HTTPS/443. Old/disabled Panels retain their existing UI.

The copyable JSON packet is protocol smi1 with panel_url, node_id, node_name,
origin, control_url, installation_code and expires_at. The response's exact Node,
domain/path/code/expiry is validated before display. The code lives only in the
mounted dialog; closing/expiry removes it, copying is explicit, and pending-code
revocation is available. Closing does NOT revoke a valid grant or clear the system
clipboard. No executable installation command is shown or generated.

Reservation and issuance are two requests. After a confirmed reservation, issue
failure retries the same Node. After an unknown/lost reservation reply, the dialog
blocks blind reservation retry and asks the operator to reconcile the Node list.
A reserved Node remains visible if issuance fails or the dialog closes. Expired or
lost codes are replaced for the same pending Node; this does not replace paired keys.

Validation: 9 offline React interaction tests, strict scoped TypeScript, production
Vite build, 13 HTTP authorization/capability tests, 6 reservation tests and 4 legacy
UI invariants PASS. UI tests cover retry/lost reply, wrong Node, invalid domain,
expiry, revoke failures, copy contract and unmount cancellation. No live browser or
real server installation was exercised. CI now runs interaction tests on the trial
branch as well as the existing API/transport regressions; check exact head results.

NEXT: U-OPTI client for this packet, durable secret staging BEFORE redemption,
resume with the exact same secret and signed lost-response recovery after expiry.
Then explicit migration/ingress setup, snapshot/recovery coverage, signed images,
and unified installer wiring. Neither feature flag is enabled by this checkpoint.

## Signed installation recovery checkpoint (2026-11-12)
Added POST /api/node-control/installation-status to the existing signed machine
allowlist. It requires the paired key and durable replay check, signed mode and
explicit origin trust. It returns only exact grant-approved Node/name/origin/path
bindings. It does not register/activate a Node or change its runtime/metadata.
Only replay nonce bookkeeping is written. Expired consumed grants and disabled
new issuance still permit proof; revoked keys and missing origin evidence fail.

Six new real-HMAC/ASGI tests PASS: expiry/issuance-off recovery, wrong key/unsigned,
replay, revocation, disabled trust/wrong scope, and missing committed evidence.
U-OPTI companion client stages a scoped secret durably before redemption and uses
this proof after lost replies or expiry. Offline cross-repository ASGI integration
verified a real redemption followed by a deliberately lost acknowledgement, expired
recovery and later revocation. Public TLS and live host installation remain untested.

NEXT: explicit schema and Nginx ingress provisioning including installation-status;
controlled promotion from client staging to runtime identity; safe retry after
promotion, snapshot/recovery coverage; signed trial images and full orchestration.
No default flag, live runtime or main change. Enrollment proof is not Connected.

## Explicit schema and HTTPS ingress design checkpoint (2026-11-12)

Trial Smite SHA: `a9a42982ffbfdf1c60c76bf4e08f277616761775`.
Companion U-OPTI ingress SHA: `e7ef316394bbf239cbc210c314075740421ea0c4`.
No host action, signed image build, default flag change or main merge.

`panel/app/foreign_install_migration.py` supplies a standalone review and an
explicit confirmation-required additive schema migration, never invoked at
application startup. It requires the existing signed pairing, incoming replay
and nodes tables, refuses partial/incorrect schemas, and uses an online SQLite
snapshot (including committed WAL data) to create a root-/service-user-owned
0600, single-link, no-overwrite backup before adding the two grant tables.
An existing, ambiguous migration backup blocks another migration attempt
rather than being overwritten. Re-runs after verified migration are read-only
and idempotent. The actual Panel DB_PATH=./data/smite.db works when resolved
inside the Panel working directory; ancestor symlinks/traversal are rejected.
No replay nonce or existing Node identity is replaced. No automatic rollback
or recovery of active grants is authorized: the backup must be retained with
the independent Panel encryption key and replay evidence for an audited
recovery plan. Both grant/trust feature flags stay disabled.

The companion U-OPTI renderer verifies the existing signed Pairing ingress
and exact U-OPTI TLS backend; it emits exact POST-only HTTPS/443 routes for
/api/foreign-install/redeem and /api/node-control/installation-status.
The former injects ONLY the trusted local ingress header from the existing
private Nginx include; the latter always strips client-supplied ingress
headers. The root Panel proxy also strips that client header for all other
paths. Existing Pairing, FRP, backhaul and root routes remain preserved.
Duplicate or drifted locations fail closed. The renderer has no apply/reload
or configuration write path in this checkpoint.

Verification: 13 new migration tests including real relative DB_PATH,
snapshots with WAL, failed migration retention, hardlink/symlink/partial
schema refusal and unchanged existing Node identity. Smite exact-source
Node Pairing Atomic Store CI 43196483303 SUCCESS and Admin UI CI
43196483549 SUCCESS. Companion U-OPTI 10 ingress template tests plus real
disposable Nginx TLS proxy test (fake certificate and local echo upstream):
forged client ingress is replaced ONLY on the grant route, stripped on
signed proof and general Panel routes, GET is denied and oversized POST
is rejected. U-OPTI run 43196231871 SUCCESS. These are isolated CI checks,
not public-CA or live two-host admission.

NEXT: signed trial Panel/Node image pair with provenance and exact digests;
then implement explicitly authorized, backup-first transactional U-OPTI host
apply and rollback for the schema, Nginx configuration and Panel flags
without changing FRP. Only after the Panel runtime is admitted, integrate
Foreign installer orchestration with identity promotion, one-time replay
provisioning and dual-direction signed connectivity. Do not activate the new
endpoints on the old immutable RC7 images.
