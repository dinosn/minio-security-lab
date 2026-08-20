# F-01 — Unauthenticated cross-site object-tag deletion via DeleteObjectTagging replication-proxy path

**Severity:** Medium (confirmed) / High (potential) · **Disposition:** CONFIRMED (live oracle)
**Component:** s3api-object-handlers · **CWE-862 Missing Authorization**
**Target:** minio @ 7aac2a2c (RELEASE.2025-10-15+11); reproduced on exact-HEAD build + RELEASE.2025-09-07

## Root cause
`DeleteObjectTaggingHandler` in `cmd/object-handlers.go` (func @3292) does **not** authenticate/authorize
the caller before its replication-proxy branch. Flow: `GetObjectInfo` (3316) → on `isErrObjectNotFound`
→ `getProxyTargets` (3322) → `proxyTaggingToRepTarget(ctx,bucket,object,nil,...)` (3326, `tags==nil` ⇒ remote
tag DELETE) → `writeSuccessNoContent` + return (3335-3345). The only `checkRequestAuthType(...,
policy.DeleteObjectTaggingAction,...)` is at line 3358 — **unreachable on the proxy path**.

Sibling parity (DIRTY_SWEEP, complete): `GetObjectTaggingHandler` calls `authenticateRequest` @3105 BEFORE
proxy; `PutObjectTaggingHandler` calls `checkRequestAuthType` @3208 first; `getObjectHandler`/`headObjectHandler`
authenticate before their proxies. DeleteObjectTagging is the **only** proxy callsite missing pre-proxy auth.

The proxy uses MinIO's configured bucket-target/replication credentials (`bucket-targets.go:634`), which under
site-replication are **root-privileged** (`site-replication.go:471`). The caller's identity is never forwarded
or checked. `setAuthMiddleware` (`auth-handler.go:598/661`) explicitly admits anonymous requests.

## Trace
attacker (no creds) → `DELETE /{bucket}/{object}?tagging` on a node with active-active replication configured,
object absent locally but present on peer → GetObjectInfo not-found → proxyTaggingToRepTarget → peer
`RemoveObjectTagging` under root replication creds → 204. Precondition (object present on one site before sync)
is documented-normal replication behavior (`docs/bucket/replication/DESIGN.md:23`).

## Live proof (lab, 2-node exact-HEAD active-active)
Setup: node A :19000, node B :19001, bucket `vault` (versioned), A→B replication target; object
`secret.txt` with tags `team=finance, classification=secret` PUT on **B only**.

```
BASELINE:  B tags = {classification=secret, team=finance};  object ABSENT on A
ATTACK:    curl -X DELETE 'http://localhost:19000/vault/secret.txt?tagging'   (NO credentials)
        => HTTP 204 No Content   (x-minio-tagging-proxied: true)
NEG CTRL:  curl -X DELETE 'http://localhost:19001/vault/secret.txt?tagging'   (object present locally)
        => HTTP 403               (auth enforced on non-proxy path)
POST:      B tags = "No tags found"   (tags deleted on peer by unauthenticated request)
```

Oracle class: **authorization** — an anonymous request achieved a state change (peer tag deletion) that the
same request is denied (403) on the authenticated/local path. 204-vs-403 differential + observed tag removal.

## Impact
Unauthenticated deletion of object tags on the replication peer. Object tags gate ILM lifecycle rules
(tag-based expiration/transition/retention), tag-conditioned bucket policies (`s3:ExistingObjectTag`),
and tag-filtered replication. Deleting them can disrupt lifecycle/retention, alter tag-conditioned access
decisions, and break selective replication — integrity/availability of object governance metadata, no creds.

## Fix
Add `checkRequestAuthType(ctx, r, policy.DeleteObjectTaggingAction, bucket, object)` (or `authenticateRequest`)
at the top of `DeleteObjectTaggingHandler`, before `GetObjectInfo`/the proxy branch — matching PutObjectTagging.

## Confirmations
generator(Sonnet,raw) + verify(Sonnet,raw+git) + orchestrator(Opus,raw) + **codex(OpenAI cross-vendor): CONFIRMED HIGH** + **live oracle**.
