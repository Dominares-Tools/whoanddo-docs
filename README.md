# whoanddo — Admin accounts, roles and an honest audit log

**Paid tool: $149 once (plus sales tax where it applies), then a private GitHub repository you're invited to, with every update. Buy: https://dominares.org/tools/whoanddo**

Commercial license v1.3 — see https://dominares.org/license · Support: support@dominares.org

whoanddo gives an admin panel per-person accounts with roles, a pure method-and-path permission check, an ASGI guard, signed session cookies, a login throttle, an audit trail that cannot be handed a name, hashed scoped API keys and single-use reset and invite links, and it scans your code for audit calls whose actor a caller can set.

## Get it

Buy whoanddo at https://dominares.org/tools/whoanddo: one payment of $149, plus sales tax where it applies, and every future update. After checkout you are invited to a private GitHub repository with the source and every version published to it. The repository includes the Python package and the whoanddo command (check, scan, accounts, keys, audit), examples, and the full test suite.

Requirements: Python 3.10 or newer, no runtime dependencies.

This page documents version 1.0.1. Install commands and file paths in the documentation below run inside the private repository you are invited to; the source is not in this repository.

## Documentation

### Why

A shared admin password tells you nothing about who did what. Per-person accounts fix that, and then the
audit log is only as honest as the line that fills its `actor` column. When that line reads a header
(`X-Actor`, `X-Admin-Username`), the log names whatever the caller typed, and it is the record you consult
when you suspect exactly that. The usual first fix rewrites the calls that read the header inline and
misses the ones that bind it to a local first (`actor = resolve_actor(request)` ... `audit(actor=actor)`),
and the check you wrote stays green.

whoanddo is the whole set of parts, each with the failure above designed out:

- **Accounts.** `AccountStore`: one JSON file, PBKDF2-HMAC-SHA256 passwords, roles `viewer` / `editor` /
  `admin` (`roles=` renames them; the CLI takes `--roles`), soft delete with restore, purge only after remove, a password change
  that ends every session the account already holds.
- **Permissions as a pure function.** `Policy.decide(method, path, role)` against a rules table that is
  plain JSON you can review in a diff. No web framework, no clock, no files.
- **Signed sessions.** HMAC-signed cookie tokens. The name and role a request carries come from the
  signature and the live account row, never from a header or a body field.
- **An audit trail that cannot be handed a name.** `AuditLog.append` takes an `Identity` (what a verified
  session returns). Passing a string raises `TypeError`; there is no default actor and no `actor=` argument.
- **A scanner for the trap.** `whoanddo scan` reads your Python and reports every audit call whose actor
  comes from request input, a fixed string, or an `Identity` built by hand, following the name through
  local variables and enclosing functions.
- **Sign-in with a throttle and alerts that cannot spam.** Failed logins are counted per address and
  blocked after a threshold; the alert for a failure fires once per address per window and says how many
  it swallowed. The break-glass owner password is always named as the owner, and a typed name is carried
  apart, labelled unverified.
- **API keys.** Shown once, stored only as a SHA-256 hash, scoped, revocable at once, with the whole gate
  (bearer header, scope, per-key rate limit) as one call that returns the status to answer with.
- **Single-use links.** Password reset, invite and email verification: only a hash is stored, each link is
  bound to one purpose and one audience, and two clicks cannot both succeed.
- **An ASGI guard** that puts it together in front of any ASGI app, with no dependencies.

Python 3.10 or newer. The runtime is the standard library only.

### Put it in front of an app

```python
import tempfile, pathlib
from whoanddo import (AccountStore, AdminGuard, AuditLog, Authenticator, Policy, Rules, SessionManager)

folder = pathlib.Path(tempfile.mkdtemp())
accounts = AccountStore(folder / "accounts.json")
accounts.upsert(username="jane", password="correct horse battery", role="editor")

sessions = SessionManager("a-long-random-secret-from-your-environment", accounts)
auth = Authenticator(accounts, sessions, notify=lambda event, payload: print(event, payload["ip"]))

rules = Rules.from_dict({
    "admin_only_prefixes": ["/admin/api/accounts"],      # the account surface: admin, for every method
    "admin_only_mutations": ["/admin/api/settings"],     # reading is fine, changing needs admin
    "read_only_posts": ["/admin/api/search"],            # a POST that only reads: a viewer may use it
})
audit = AuditLog(folder / "audit.jsonl")

async def app(scope, receive, send):                     # any ASGI app: Starlette, FastAPI, your own
    who = scope["whoanddo.identity"]                     # proven by the signed cookie
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b""})

app = AdminGuard(app, policy=Policy(rules), sessions=sessions, audit=audit,
                 prefixes=("/admin/api/",), public_paths=("/admin/api/login",))

result = auth.login(username="jane", password="correct horse battery", ip="203.0.113.7", user_agent="curl")
print(result.status, result.kind, result.role)           # 200 account editor
cookie = sessions.cookie(result.token, secure=True)      # the Set-Cookie value for your login handler
```

Your login handler calls `auth.login(...)` and on success sends `sessions.cookie(token, secure=...)`. Use
`cookie_secure(headers, scheme)` to decide `secure`: behind a proxy that terminates TLS the scheme the app
sees is `http`, and the helper follows `X-Forwarded-Proto` instead. `client_ip(forwarded_for, peer,
trusted_hops=1)` gives the address to throttle on. Set `trusted_hops` to the number of proxies you run in
front of the app: it takes the entry the last of them appended, never one further left that a client can
forge. With no proxy, pass `trusted_hops=0` and it always returns the TCP peer (a client-sent
`X-Forwarded-For` is then ignored). `AdminGuard` defaults to `trusted_hops=0` for the audit `client` column;
set it to your proxy count behind one.

With the guard in place: no valid session is a 401, a role that may not do the thing is a 403 with the
reason, everything else reaches the app with `scope["whoanddo.identity"]` set. Every write by a signed-in
user, and every request refused to one with a 403 or a 400, is appended to the audit log under the signed
name after the status is known. A request with no valid session (401) writes no row, because there is no
signed name to put on it.

A guarded path that contains a `.` or `..` segment or a doubled slash is refused with a 400 once the caller
is signed in and allowed, and with a 401 when they are not. The guard decides on the resolved path while your
router routes on the raw one, so a request that means two things to them never reaches the app.
`public_paths` match only the plain form of a path (a trailing slash is fine).

### The rules table

Every field is optional and every path starts with `/`. The first check that applies decides:

| Field | Meaning |
|---|---|
| `admin_only_prefixes` | needs admin, any method |
| `admin_only_reads` | needs admin even for a GET (a dump of every account's hash) |
| `write_only_reads` | needs editor even for a GET (personal data a read-only role should not see) |
| `admin_only_mutations`, `admin_only_mutation_prefixes` | changing it needs admin; a GET stays a plain read |
| `read_only_posts`, `read_only_post_prefixes`, `self_service_posts` | a POST that persists nothing, or a person changing their own password: every known role |
| `mutating_reads` | GETs that fire a side effect (a sync, a test email): treated as writes |
| `read_methods` | default `GET`, `HEAD`, `OPTIONS`; any other method counts as a mutation |
| `read_role`, `write_role`, `admin_role` | rename the three roles |

Anything else that mutates needs the write role; anything else that reads is open to every known role.
A prefix matches on a path-segment boundary (`/accounts` covers `/accounts/jane`, not `/accounts-export`;
write `/preview/` to match only what is under it). Paths are normalised first (query and fragment dropped,
`//`, `.`, `..` and `%xx` resolved), so `/x/../admin/api/accounts` cannot dodge a rule; `AdminGuard`
additionally refuses such a path outright (see above). `examples/rules.example.json`
is a complete file.

Check a rule from the shell:

```bash
whoanddo check POST /admin/api/accounts viewer --rules examples/rules.example.json   # deny_admin_only, exit 1
whoanddo check POST /admin/api/notes --rules examples/rules.example.json             # the answer for every role
```

### Accounts, sessions, sign-in

- `AccountStore(path)`: `upsert`, `set_role`, `reset_password`, `remove` (soft), `restore`, `purge` (only an
  already-removed account), `list(include_deleted=...)`, `get`, `verify`, `note_login`, `find_by_email`,
  `session_generation`. A listed row never carries a hash. `verify` costs a hash even for an unknown name.
- A store file that exists but cannot be parsed raises `StoreError` and is never overwritten, and it signs
  nobody in.
- `SessionManager(secret, accounts)`: `issue_for_account`, `verify`, `identify(cookie_header)`, `cookie`.
  An account session is checked against the live account on every request: remove the account or change
  its password and the session is dead; change its role and the new role applies on the next request. The
  secret must be at least 16 characters. `derive_secret(base, password)` gives a secret that changes when
  the password does.
- `Authenticator.login(...)`: throttle, check, session, alert, in that order (see the module docstring).
  Pass `master_password=` only if you want a break-glass owner sign-in; without it, an empty account store
  signs nobody in. `notify` is any callable `(event, payload)`; whatever it does (a chat message, an email)
  is yours, and an exception in it never breaks a sign-in.

### The audit log

```python
cookie_header = f"{sessions.cookie_name}={result.token}"     # what the browser sends back on the next request
audit.append(identity=sessions.identify(cookie_header), method="POST", path="/admin/api/notes", status_code=201)
audit.read(limit=50)                          # newest first
audit.find(actor="jane", path_prefix="/admin/api/accounts")
```

Rows hold the time, `actor`, `actor_kind` (`account`, `owner`, `key`, `anonymous`), `actor_role`, method,
path, status, client and a short list of headers. Secret-looking keys (`password`, `token`, `authorization`,
`api_key`, `secret`, `cookie`, ...) are redacted, long strings are cut at 500 characters, and only
`user-agent`, `referer`, `origin`, `x-forwarded-for` and `x-real-ip` are kept. The file rotates once at
8 MB (the previous `.1` is replaced); reads cover both files.

#### Check your own code

```bash
whoanddo scan src/          # exit 1 and file:line:col for each finding; exit 2 if a path is missing,
                            # holds no Python, or a file would not parse
```

It reports a call whose callee name contains `audit` and that passes `actor=`, `operator=` or `identity=`
when the value (a) comes from `.headers`, `.cookies`, `.query_params`, `.args`, `.form` or a helper such as
`resolve_actor`, (b) is a string literal, or (c) is an `Identity(...)` built on the spot. A name is followed
back through `=`, `:=`, `+=`, `for` and `with ... as` targets, comprehensions, enclosing functions and
module-level constants, so `who = "admin"` ... `audit.append(actor=who)` is reported like the inline form.
(A literal is only reported when it is the whole value, not part of `f"{prefix}:{uid}"`.) Calls to
`identify`, `verify` and `signed_actor` are trusted. Add your own with `--sink NAME`, `--kwarg NAME`,
`--tainted-call NAME`, `--clean-call NAME`. Put it in CI.

### API keys and single-use links

```python
from whoanddo import KeyStore, RateLimiter, LinkStore, RESET

keys = KeyStore(folder / "keys.json", prefix="acme_")
issued = keys.issue(label="partner", scopes=["reports:read"])      # issued["key"] is shown this once
decision = keys.authenticate("Bearer " + issued["key"], "reports:read", limiter=RateLimiter(60, 60))
print(decision.status)                                              # 200; 401 / 403 / 429 / 503 otherwise

links = LinkStore(folder / "links.json", "a-long-random-secret-from-your-environment")
token, row = links.issue(kind=RESET, audience="site-1", username="jane")   # lives 45 minutes
print(links.peek(token, kind=RESET, audience="site-1")["username"])      # reading does not spend it
print(links.consume(token, kind=RESET, audience="site-1") is not None)   # True once, then never
```

`audience` is any string you choose to bind a link to (a site, a tenant, an organisation). Reset links live
45 minutes, invites 7 days, verification links 24 hours; pass `ttl=` for anything else. Issuing an invite
revokes the earlier pending invite for the same person. `sign_stateless` / `verify_stateless` make a signed
token with nothing stored, for confirmations that need no single-use enforcement.

### Command line

```
whoanddo check METHOD PATH [ROLE] --rules FILE
whoanddo scan PATH... [--sink S] [--kwarg K] [--tainted-call F] [--clean-call F]
whoanddo accounts --file F [--roles A,B,C] [--default-role R]  list [--all] | add NAME [--role R] [--password-stdin] | role NAME ROLE
                            | passwd NAME | verify NAME | remove NAME | restore NAME | purge NAME
whoanddo keys --file F [--prefix P]  issue LABEL [--scope S]... | list | revoke ID
whoanddo audit --file F [-n 20]
```

Passwords are read from a prompt, or from stdin with `--password-stdin`; they are never taken as arguments.

### Limits

- **Accounts with a role the store was not given are left alone, not used.** Open a file with the same
  `roles` it was written with (or `--roles` on the CLI); otherwise those accounts cannot sign in or be listed,
  but no write ever deletes them.
- **Files, not a database.** Accounts, keys, links and the audit log are JSON files with a lock around each
  change (`fcntl` on POSIX, so separate processes are safe; on Windows only threads in one process are).
  That suits tens of accounts and moderate traffic, not thousands of writes a second.
- **One process remembers throttle state.** Attempts are counted before the password check, so at most
  `threshold` guesses per address are checked per window even when sent at once. The login throttle, the alert debounce and the key rate limiter
  live in memory: a restart resets them and several workers each keep their own count.
- **No second factor, no SSO, no password-strength or breach checks** beyond a minimum length (8). The
  throttle counts failures per address, not per account, so a spread-out guessing attempt is not slowed by
  it. Leading and trailing spaces in a password are ignored.
- **Sessions are stateless.** There is no list of live sessions to revoke one by one; a session ends when it
  expires, when its account is removed or its password changes, or when you change the signing secret.
- **The scanner reads source; it does not run it.** It follows assignments inside the file, but a value that
  arrives as a function parameter, from another module or through a container is not followed, and only
  keyword arguments are checked. It is a guard against the common shapes, not a proof.
- **Not covered:** multi-tenant isolation, billing or plan gating, sending any mail or chat message (you
  supply `notify`), and the web UI. It does not ship a loose "announced name" helper on purpose.
- **Deliberate differences from a "no lockout" design.** An empty or unknown role is denied rather than
  treated as admin; an unknown HTTP method counts as a write; an error while deciding refuses the request
  unless you pass `fail_open=True` to `AdminGuard`.

### Tests

```bash
python -m pytest
```

---

Docs mirror of the private repository Dominares-Tools/whoanddo; updated with each release.
