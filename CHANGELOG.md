# Changelog

## 1.0.1 (2026-10-05)

Security and correctness fixes from review of 1.0.0. Upgrade.

- Fixed: `AdminGuard` decided on the dot-resolved path while the wrapped app routed on the raw one, so
  `DELETE /admin/api/files/../../../x` reached a `{p:path}` route with no session. A request is now guarded
  when either form is under a prefix, and a guarded path with a `.`/`..` segment or a doubled slash gets 401
  (no session), 403 (not allowed) or 400 (allowed but ambiguous). `public_paths` match only the plain path.
- Fixed: `AccountStore` dropped every row whose role it was not given on its next write, so the CLI could wipe
  an app's accounts. Unusable rows are now kept untouched through every write; adding a name such a row holds
  is refused. `whoanddo accounts` gained `--roles` and `--default-role`.
- Fixed: the login throttle was checked before, and counted after, the slow password check, so simultaneous
  guesses all passed. The attempt is now reserved under the lock and forgiven on success.
- Fixed: `whoanddo scan` on a missing path, or a folder with no Python, reported a clean scan and exited 0;
  it now exits 2.
- Fixed: the scanner now follows a fixed name or hand-built `Identity` bound to a local or a module constant,
  and `for`, `with ... as` and comprehension targets, as documented.
- Changed: `client_ip(..., trusted_hops=0)` means no proxy and always returns the TCP peer; a negative value is
  refused. `AdminGuard` now defaults to `trusted_hops=0`; set it to your proxy count behind one.
- Docs: the README says exactly which refused requests are audited. Removed an unused internal field and
  leftover wording in the alert docstrings; the owner alert's detail label is now "Typed username (unverified)".

## 1.0.0 (2026-10-05)

First release.

- `AccountStore`: per-person accounts in one JSON file with roles, soft delete, restore, purge, and a
  session generation that a password change bumps.
- `Policy` / `Rules`: a pure `(method, path, role)` permission check driven by a JSON rules table, with path
  normalisation, segment-boundary prefixes and fail-closed handling of unknown roles and methods.
- `SessionSigner` / `SessionManager`: HMAC-signed session tokens; an account session is checked against the
  live account (removed, password changed, role changed) on every request. Cookie, `cookie_secure` and
  `client_ip` helpers.
- `AuditLog`: append-only JSON lines that take an `Identity`, never a free-text actor; redaction, rotation,
  newest-first reads across both files.
- `scan_source` / `scan_paths` and `whoanddo scan`: finds audit calls whose actor comes from request input,
  a fixed string or a hand-built `Identity`, following local bindings through enclosing functions.
- `alerts` (pure) and `Authenticator`: per-address login throttle, debounced failure alerts that count the
  attempts they swallowed, owner sign-in named as the owner with the typed name carried as unverified.
- `KeyStore`, `RateLimiter`: hashed, scoped, show-once API keys and the whole bearer gate.
- `LinkStore`, `sign_stateless`, `verify_stateless`: single-use reset / invite / verify links bound to a
  purpose and an audience, and stateless signed tokens.
- `AdminGuard`: a dependency-free ASGI guard (401, 403, audit of writes).
- `whoanddo` command: `check`, `scan`, `accounts`, `keys`, `audit`.
