# Simple, secure admin sessions — experimental branch, not deployed

## What the operator sees

- The **Login** page keeps three simple fields: username, password, and
  an optional authenticator/recovery code. The server requires the code
  once two-factor authentication has been enabled.
- **Settings → Two-step sign-in** lets the operator confirm the existing
  password, scan a locally generated QR code, verify a 6-digit code, and
  save one-time recovery codes. A lost authenticator may be recovered
  using one of the previously saved codes. There is no external QR API.
- **Logout / خروج** now explicitly means **sign out on all devices**,
  not just remove this browser's access token.
- If the server cannot confirm logout (for example during a network
  outage), the UI explains the failure and offers a retry. It does
  **not** pretend to have revoked a valid token.
- Disabling two-factor authentication requires password + code, revokes
  previous tokens, and immediately clears the local browser session.

## Security implementation

- Panel JWTs carry a database-backed `auth_version` claim. Successful
  `POST /api/auth/logout` requires the current JWT, atomically increments
  that account's `auth_version` using a guarded SQL UPDATE, and
  invalidates **all** previously issued tokens for that admin.
  Even simultaneous tokens issued by different devices are rejected.
- A stale, forged, or no-MFA JWT cannot call logout without successful
  `get_current_user`. Concurrent or changed account versions fail
  closed. JWTs cannot be reactivated by revisiting a URL.
- The existing 2FA implementation stores authenticator secrets encrypted
  with Fernet, recovery codes as keyed digests only, and tracks used
  TOTP time steps to prevent replay. Five invalid MFA submissions
  trigger a short account-specific lock.
- The `/api/auth/logout` response contains no new access token and sets
  `Cache-Control: no-store`.
- **Tradeoff:** Sign-out revokes sessions on *all* devices for that
  admin. This is intentional and labeled in the UI. It is not a
  per-device session manager.
- **Tradeoff:** A network failure cannot prove server-side revocation.
  The UI retains the original session and offers a retry rather than
  claiming a successful logout. The user may also close the browser,
  but that alone does not revoke remote JWTs.
- **Remaining work:** no public production rollout, penetration test,
  or complete password brute-force review has been claimed. A
  deployable two-host release still requires the independent engine
  lifecycle and snapshot/443 acceptance gates.

## CI checks

- `tests/test_totp_mfa.py`: real disposable SQLite + FastAPI
  authenticator enrollment, recovery, one-use/replay checks.
- `tests/test_session_logout.py`: real database + FastAPI two-device
  token revocation, unauthenticated denial, stale version rejection,
  and strict MFA JWT requirement.
- `frontend/tests/mfaSecurity.test.cjs`: existing login remains
  easy to use; transient logout failure must not silently delete a
  session; 2FA disable clears an already invalidated token.
- Changes remain on `feature/smite-simple-operator-ui-20261018`
  (Draft PR #15). Neither `main` nor live IR/KH was changed.
