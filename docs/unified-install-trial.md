# Unified installation trial: Foreign installation grants

Branch: trial/unified-smite-install. Status: store and default-OFF HTTP adapters implemented; not a host-installable release.
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
- The new origin table is inert. Add a gated trusted-origin reader, ensuring no
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
Implement gated database origin lookup with file/DB conflict and identity
revocation checks, plus public-IP DNS pinning for the new origin source. Then
admin UI, durable client identity staging, signed lost-reply verification,
snapshot/recovery coverage, signed trial images and U-OPTI orchestration.
Do not enable the new flag or advertise a host install command at this checkpoint.
The external Nginx endpoint/ingress configuration is not wired yet.
