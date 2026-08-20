# F-02 — Cross-account IAM identity destruction via path traversal in service-account access key

**Severity:** High (confirmed) / High-Critical (potential) · **Disposition:** CONFIRMED (live oracle, persists across reload)
**Component:** auth-iam-store / admin-api-users-svcacct · **CWE-22 Path Traversal + CWE-863**
**Target:** minio @ 7aac2a2c; reproduced on exact-HEAD build (node A :19000)

## Root cause
`getUserIdentityPath(accessKey, svcUser)` (cmd/iam-store.go:105) = `pathJoin(iamConfigServiceAccountsPrefix,
accessKey, iamIdentityFile)`. `pathJoin` runs `path.Clean`. Service-account access keys are validated only by
`auth.IsAccessKeyValid` (internal/auth/credentials.go:79 — **length 3–20 only**; reserved chars are just `=`,`,`).
Unlike regular `AddUser` (whose raw name is rejected for `..`/`.`), the service-account create path never
rejects `..` in the access key, and `path.Clean` collapses it BEFORE the object write, so the guard on the
object name (`ErrObjectNames "bad components .. or ."`) never fires. Result: access key `../users/<victim>`
→ `config/iam/service-accounts/../users/<victim>/identity.json` → cleaned → `config/iam/users/<victim>/identity.json`,
**overwriting the target regular user's identity object.** (Same mechanism reaches `getMappedPolicyPath` →
`policydb/users/<victim>.json`.)

## Attacker / privilege
**Any authenticated user** — creating a service account *for oneself* is default-allowed (no `admin:*` action
required). The traversal is in the attacker's own service-account access key; the parent is the attacker.
Confirmed live with an attacker holding ONLY `s3:GetObject`/`s3:PutObject` (verified non-admin: `mc admin info`
denied).

## Trace
attacker (non-admin) → `AddServiceAccount` (self) with `--access-key ../users/<victim>` → iam-store
`saveIAMConfig(getUserIdentityPath("../users/<victim>", svcUser))` → object write to cleaned path
`config/iam/users/<victim>/identity.json` → overwrites victim's identity → on IAM reload the victim regular
user no longer exists / original creds invalid.

## Live proof (exact-HEAD node A)
```
SETUP:   victimuser2 (policy ro-a) reads tenant-a/o.txt = "victim-data";  attacker1 = non-admin (mc admin info -> denied)
ATTACK:  as attacker1 -> mc admin user svcacct add ATK attacker1 --access-key "../users/victimuser2" --secret-key evil12345
      => ACCEPTED (Secret Key: evil12345, no-expiry)   [in-memory: victim still works — overwrite masked]
RELOAD:  restart node A (forces IAM load from disk)
POST:    victimuser2 + original secret -> "not found" (auth broken);  victimuser2 REMOVED from user list;  attacker still non-admin
ON-DISK: config/iam/service-accounts/ is EMPTY; the svcacct landed at config/iam/users/victimuser2/identity.json (single xl.meta, mtime=attack)
```
Oracle class: **state-change/integrity** — a low-privilege request persistently destroyed another account's
identity object (cross-privilege boundary); confirmed by pre/post auth differential + on-disk path landing +
survival across reload.

## Impact
Any authenticated user can **permanently destroy/overwrite the identity of an arbitrary target account**
(regular users, and — name length ≤11 permitting, since key ≤20 and `../users/` = 9 — other admins),
a cross-account integrity/availability attack on the IAM control plane. Root (env-provided) is not stored in
the IAM object store and is not a target. Clean *takeover* (auth AS the victim with a known secret) is not
proven — the stored credential's AccessKey field is the crafted traversal string, so auth-by-victim-name
mismatches — but destruction/lockout is proven and persistent.

## Fix
Validate service-account (and STS) access keys the same way regular user names are validated: reject any key
containing `/`, `..`, or `.` path components before it is used as a storage path segment (or reject at
`IsAccessKeyValid`). Do not rely on `path.Clean`, which realizes the collision instead of rejecting it.

## Confirmations
generator(Sonnet,raw) + verify(Sonnet,raw+git) + **codex(OpenAI cross-vendor): CONFIRMED High** (decisive:
object-api-utils.go:295 `path.Clean` realizes collision) + **live oracle (non-admin destruction, persists across reload)**.
DIRTY_SWEEP: sink = IAM store writes keyed by an attacker-influenced name segment (see TRIED.md).
