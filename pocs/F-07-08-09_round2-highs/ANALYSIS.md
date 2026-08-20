# F-07 / F-08 / F-09 — Round 2 high-severity findings (codex cross-vendor confirmed)

## F-07 — Privilege escalation to ROOT via SRPeerJoin service-account parent forgery (CRITICAL)
**Component:** admin-api-site-replication · CWE-269/CWE-863 · **Disposition: CONFIRMED-DEFECT (codex CRITICAL) / live-exploit pending madmin-encrypted body**

Root cause: `SRPeerJoin` (cmd/admin-handlers-site-replication.go:80) is gated ONLY by `admin:SiteReplicationAdd`
with **no authenticated-peer / shared-secret check**. Its body is madmin-encrypted with the *caller's own*
secret (line 89), so any holder of the action can construct it. `PeerJoinReq` (cmd/site-replication.go:626)
passes the attacker-supplied `SvcAcctParent`, `SvcAcctAccessKey`, `SvcAcctSecretKey` **directly** into
`globalIAMSys.NewServiceAccount()`. With no session policy, the service account inherits its named parent's
policy (cmd/iam.go:1103, 2214) — **parent=root ⇒ full admin**. Reachable *before* site replication is
configured (no `isEnabled()` prereq; saving the supplied peer map enables SR, site-replication.go:657/321).
The only deployment check is that the attacker-controlled `Peers` list contains the current deployment ID
(site-replication.go:615), which is obtainable from any S3 response.

Impact: an admin-area principal holding just `admin:SiteReplicationAdd` mints a root-parented service account
(attacker-chosen key+secret) → full admin/root takeover.

Confirmations: generator(Sonnet) + **codex(OpenAI) CONFIRMED CRITICAL** (line-by-line gate-fail evidence).
codex reliability calibrated by F-08 live-confirmation.

Exact live test (Go + madmin, for the operator):
1. Create user U with policy `{"Action":["admin:SiteReplicationAdd"]}`.
2. Read deployment ID D (unauth) from any S3 response header / `mc admin info`.
3. Go: `body,_ := madmin.EncryptData(U.secret, json({Peers:{D:{...}}, SvcAcctParent:"minioadmin", SvcAcctAccessKey:"pwn", SvcAcctSecretKey:"pwnsecret123", ...}))`; SigV4-sign PUT /minio/admin/v3/site-replication/peer/join with U's creds, body.
4. Auth with pwn/pwnsecret123 → run `mc admin user list` (admin op) → expect success (root-inherited).

Fix: require a mutual peer authentication (shared join token) for SRPeerJoin; bind `SvcAcctParent` to the
authenticated caller / the actual joining peer identity; never accept an arbitrary parent from the request.

---
## F-08 — Batch-job exfiltration of any bucket via admin:StartBatchJob (HIGH) — CONFIRMED LIVE
**Component:** batch-jobs · CWE-863 · **Disposition: CONFIRMED (live oracle)**

Root cause: `StartBatchJob` (cmd/batch-handlers.go:1749) is gated only by `admin:StartBatchJob`.
`BatchJobReplicateV1.Validate()` (1388) checks the source/target bucket *exists*, never the submitter's
`ListBucket`/`GetObject`. The queued job replaces the request context with the **global worker context**
(1800/2056) and reads the source via unrestricted internal `ObjectLayer` calls (1248/700) — i.e. with MinIO's
own authority, not the caller's. Target writes use attacker-supplied target credentials (1146).

Live proof (exact-HEAD node A):
```
batchuser policy = admin:StartBatchJob + s3:* on exfil-bkt ONLY (no access to secret-bkt)
control: mc cat BU/secret-bkt/private.txt -> "Insufficient permissions" (cannot read)
attack:  mc batch start BU replicate{source: secret-bkt, target: exfil-bkt (batchuser creds)} -> job started
result:  mc cat BU/exfil-bkt/private.txt -> "TOP-SECRET-BATCH-EXFIL"   (private bucket exfiltrated)
```
Oracle class: authorization — a principal with no read on secret-bkt exfiltrated its contents.
Blast radius: every local user bucket (per-object SSE-C can still block individual reads).

Fix: authorize the submitting credential against Source (read) and Target (write) buckets before enqueuing,
and/or run the job under the submitter's policy, not the global worker authority.

---
## F-09 — Fan-out upload key-authorization bypass (HIGH)
**Component:** s3api-postpolicyform · CWE-863 · **Disposition: CONFIRMED-DEFECT (codex HIGH)**

Root cause: `PostPolicyBucketHandler` evaluates the SigV4 signature, POST policy, and `s3:PutObjectFanOut`
ONLY against the outer `Key` form field (cmd/bucket-handlers.go:1136/1159). The `x-minio-fanout-list` part is
decoded and deliberately omitted from `formValues` (1016/1241), so `checkPostPolicy()` never sees the fan-out
keys; each `req.Key` reaches internal `PutObject` unchecked (cmd/post-policy-fan-out.go:113).

Impact: a principal authorized to fan-out-upload to bucket X (e.g. policy restricting them to `prefixA/*`) can
write **arbitrary keys anywhere in bucket X** (overwrite `prefixB/*`), bypassing the prefix restriction.
Scope: **bucket-local** (codex corrected the generator's cross-bucket claim — entries carry only keys, the
bucket is fixed to the request bucket).

Fix: apply the POST policy conditions and an IAM PutObject authorization to EACH fan-out entry key, not only
the outer Key.
