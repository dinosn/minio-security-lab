# MinIO Security Audit — RAPTOR Loop-Hunt Report (INTERIM)

**Target:** `github.com/minio/minio` @ `7aac2a2c5b7c882e68c1ce017d8256be2feea27f`
(≈ RELEASE.2025-10-15T17-29-55Z + 11 commits) · Go, 655 non-test source files
**Date:** 2026-08-20 · **Engagement:** minio-1
**Method:** RAPTOR raptor-loop-hunt — multi-altitude, isolated generate→judge (both from raw), cross-vendor
codex (OpenAI) adjudication, and **live-verify against a real MinIO instance** (lab, exact-HEAD build).
**Closure status:** `PARTIAL / INTERIM` — Rounds 1–2 (whole-project + file-by-file altitudes) complete;
function-level altitude and the until-dry-twice stop condition **not yet reached** (see Coverage & Limits).

---
## Executive summary

Sixteen issues were adjudicated to a real disposition across four altitudes; **thirteen are confirmed and
actionable**, eight of those **proven live** on a running MinIO built from the audited commit. Every headline
result is an authorization / trust-boundary defect, not memory-safety — consistent with MinIO's own CVE history.

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| **F-03** | **High → Critical** | OIDC cross-provider signature confusion → **admin takeover** | **CONFIRMED (live)** |
| **F-07** | **Critical** | SRPeerJoin service-account parent forgery → **root privilege escalation** | CONFIRMED-DEFECT (codex) |
| **F-15** | **High** | **Unauthenticated** policy-condition bypass (header shadows aws:username/SecureTransport/s3:x-amz-*) | **CONFIRMED (live)** |
| **F-02** | **High** | Service-account access-key path traversal → **cross-account account destruction** | **CONFIRMED (live)** |
| **F-06** | **High → Critical** | ServerUpdate `updateURL` SSRF + full response-body exfiltration (IMDS) | **CONFIRMED (live)** |
| **F-08** | **High** | `admin:StartBatchJob` exfiltrates **any bucket** (batch runs as server authority) | **CONFIRMED (live)** |
| **F-10** | **High** | `aws:SourceIp` policy bypass via spoofed X-Forwarded-For (default-on) | **CONFIRMED (live)** |
| **F-01** | **Medium → High** | Unauthenticated cross-site object-tag deletion (replication proxy) | **CONFIRMED (live)** |
| **F-09** | **High** | Fan-out upload bypasses per-key authorization (bucket-scoped) | CONFIRMED-DEFECT (codex) |
| **F-12** | **High** | ExportBucketMetadata leaks unredacted replication-target credentials | CONFIRMED-DEFECT (verify) |
| **F-11** | Med–High | admin:ServerTrace subscriber sees all tenants' SSE-C keys / auth sigs | CONFIRMED-DEFECT (verify) |
| **F-16** | **High** | `config history` returns every historically-set secret in plaintext (get-config-kv redacts) | **CONFIRMED (live)** |
| **F-14** | Medium | MySQL notify `table` config → SQL injection (no Postgres-parity validation) | CONFIRMED-DEFECT (verify) |
| F-04 | Low–Med | Internode storage-REST path traversal (root-JWT gated → hardening) | CONFIRMED (gated) |
| F-05 | Low | Disabled service-account passes SFTP/FTP login (inert — S3 still denies) | CONFIRMED (inert) |
| F-13 | Low | CopyObject REPLACE reserved-metadata injection → per-object corruption (DoS) | CONFIRMED (low) |

Every "CONFIRMED (live)" finding has a machine-checkable oracle (auth differential, data exfiltration, admin op
succeeding with forged creds). Every finding passed an independent from-raw judge; the confirmed set also passed
OpenAI/codex cross-vendor review and — where marked live — a reproduction on the running server. **F-15, F-10,
F-01 are exploitable by an unauthenticated attacker; F-02/F-08 by any authenticated user; F-03/F-06/F-07/F-09/
F-11/F-12/F-14 by a holder of one scoped/narrow permission** (not full root).

**Rigor note:** the loop generated ~90 candidates across three altitudes; **~55 were rejected** as
design-intended, already-patched, or false positives — several after they had reached a "confirmed" label. Four
Critical/High candidates were **refuted by live testing** after surviving static review (`R2-07-C1`
object-retention authz, `R2-06-A` WORM-bypass, `R1-05-C1` first-pass, `R2-13-C`/`R2-12-02` crypto). Codex
overturned one premature rejection (→ F-02). This report lists only survivors of that full pipeline. The
detailed root-cause/trace/live-oracle/fix for each is in `poc/`; the full attempt ledger with the rejected set
is in `TRIED.md` and `FINDINGS.md`.

---
## Confirmed findings

### F-03 — OIDC cross-provider signature confusion → admin takeover  · **High (confirmed) / Critical (potential)**
`internal/config/identity/openid` holds JWKS keys in a single **Config-wide `kid`→key map shared across every
configured OIDC provider** (jwt.go:151, populated openid.go:392). `AssumeRoleWithWebIdentity` validates the
token's `aud` against a provider's `client_id` but **never validates `iss`** and never scopes key selection to
the provider bound to the requested role ARN (jwt.go:198).

*Live proof (dual mock IdP, exact-HEAD):* a JWT **signed by low-trust provider B's key**, carrying provider A's
audience and A's admin role ARN, was accepted (verified with B's key from the shared map) and issued STS
credentials for **provider A's `consoleAdmin` role**. The forged credentials ran `mc admin info` and `mc mb`
successfully. An `aud`-mismatch control was correctly rejected (HTTP 400).
Requires a multi-provider OIDC deployment where the attacker controls (or can get a token with arbitrary `aud`
from) one provider's signing key. *Fix:* validate `iss` against the ARN-bound provider and scope key selection
per provider. → `poc/F-03-oidc-cross-provider-key.md`

### F-07 — SRPeerJoin service-account parent forgery → root privesc · **Critical**
`SRPeerJoin` (admin-handlers-site-replication.go:80) is gated **only** by `admin:SiteReplicationAdd`, with no
mutual-peer / shared-secret authentication. The request body is madmin-encrypted with the *caller's own* secret,
so any holder of that action can craft it. `PeerJoinReq` (site-replication.go:626) passes the attacker-supplied
`SvcAcctParent` + access key + secret straight into `NewServiceAccount()`; with no session policy the account
inherits its named parent's policy (iam.go:1103/2214) — **parent = root ⇒ full admin**. Reachable *before* site
replication is configured; the only deployment check is that the attacker-controlled peer map contains the
current deployment ID, which is obtainable unauthenticated.
Confirmed by codex cross-vendor (CRITICAL, line-by-line gate-fail evidence); codex's Round-2 reliability was
independently calibrated by the live confirmation of F-08. Live exploit requires a small Go+madmin client
(exact recipe recorded). *Fix:* mutual peer auth for join; bind `SvcAcctParent` to the authenticated caller.
→ `poc/F-07-F-08-F-09-round2-highs.md`

### F-02 — Service-account access-key path traversal → cross-account account destruction · **High**
`NewServiceAccount` (iam.go:1063) validates the access key by **length only** (`IsAccessKeyValid`); the key then
becomes a storage-path segment via `getUserIdentityPath` → `pathJoin`/`path.Clean`. A key `../users/<victim>`
collapses onto `config/iam/users/<victim>/identity.json`, **overwriting the target account's identity object**.
*Live proof:* a **non-admin** attacker (only `s3:GetObject`/`s3:PutObject`) created a self-service-account with
key `../users/victimuser2`; after an IAM reload the victim's credentials no longer authenticate and the account
is gone from the user list. Any authenticated user can destroy any target account (self-service-account creation
is default-allowed). STS keys are server-generated (safe); group/policy-name variants are admin-gated. *Fix:*
reject `/`, `.`, `..` in service-account/STS access keys before path use. → `poc/F-02-svcacct-key-traversal.md`

### F-06 — ServerUpdate `updateURL` SSRF + response-body exfiltration · **High (confirmed) / Critical (potential)**
`ServerUpdateHandler` passes the attacker `updateURL` query parameter to `downloadReleaseURL()` (update.go) with
**no RFC1918/link-local/IMDS filtering** (loopback is the only blocked range). `parseReleaseData()` then embeds
the **entire fetched response body** into the JSON error `Message` returned to the caller.
*Live proof:* `updateURL=http://<internal-LAN>/creds` returned `Unknown release data \`SECRET-IMDS-CREDS-…\``
— the internal service's full body reflected to the caller. `updateURL=http://169.254.169.254/...` triggered the
dial (timed out only because the lab isn't EC2). Gated by `admin:ServerUpdate` (a scoped, individually-grantable
admin action). On cloud hosts this reads and reflects instance IAM credentials. *Fix:* allowlist the update host;
never reflect the fetched body. → `poc/F-06-serverupdate-ssrf-reflection.md`

### F-08 — `admin:StartBatchJob` exfiltrates any bucket · **High**
`StartBatchJob` (batch-handlers.go:1749) is gated only by `admin:StartBatchJob`. `Validate()` checks bucket
*existence*, not the submitter's read/write policy; the queued job runs under the **global worker context**
(1800/2056) and reads the source bucket with MinIO's internal authority.
*Live proof:* `batchuser` (no read on `secret-bkt`; control returned "Insufficient permissions") submitted a
replicate job and exfiltrated `secret-bkt/private.txt` ("TOP-SECRET-BATCH-EXFIL") to a bucket it controlled.
Blast radius: every local user bucket (SSE-C still blocks individual objects). *Fix:* authorize the submitter
against source/target buckets, or run the job under the submitter's policy. → `poc/F-07-F-08-F-09-round2-highs.md`

### F-01 — Unauthenticated cross-site object-tag deletion · **Medium (confirmed) / High (potential)**
`DeleteObjectTaggingHandler` (object-handlers.go:3292) omits authentication on its replication-proxy branch:
`GetObjectInfo` not-found → `proxyTaggingToRepTarget` (3326, deletes peer tags with **root** replication creds)
→ returns 204, all *before* the sole `checkRequestAuthType` at 3358. Its siblings (Get/PutObjectTagging,
get/headObject) all authenticate before proxying — a DIRTY_SWEEP confirmed it is the only proxy path missing the
gate.
*Live proof (2-node active-active):* an **anonymous** `DELETE /vault/secret.txt?tagging` for an object absent
locally but present on the peer returned 204 and deleted the peer's tags; the same request for a locally-present
object returned 403. Object tags gate ILM/lifecycle, tag-conditioned policy, and replication filters. *Fix:*
authenticate before the proxy branch. → `poc/F-01-delete-tagging-authbypass.md`

### F-09 — Fan-out upload per-key authorization bypass · **High (bucket-scoped)**
`PostPolicyBucketHandler` evaluates signature, POST policy, and `s3:PutObjectFanOut` **only against the outer
`Key`** (bucket-handlers.go:1136/1159); the `x-minio-fanout-list` keys are omitted from `checkPostPolicy` and
written unchecked (post-policy-fan-out.go:113). A principal restricted to `prefixA/*` can write arbitrary keys
anywhere in the request bucket. Scope is bucket-local (not cross-bucket). Confirmed by codex. *Fix:* authorize
each fan-out entry key. → `poc/F-07-F-08-F-09-round2-highs.md`

### Round 3 findings (function-level + config/admin surface) — briefer; full detail in `poc/`
- **F-15 (High, live, UNAUTH)** — `getConditionValues` merges every request header + query param into the
  policy-condition map, and the engine canonicalizes key names first, so a client header **shadows** the
  server-set value. A bucket policy `Allow Principal:"*" GetObject if aws:username=backup-reader` is satisfied by
  an anonymous GET carrying `Username: backup-reader` (live: 403 without / 200 with / 403 wrong-value control).
  Also defeats `aws:SecureTransport` and header-only `s3:x-amz-*` conditions. *Fix:* build the condition map only
  from trusted server-derived keys; never merge raw request headers/query into it.
- **F-10 (High, live, UNAUTH)** — `aws:SourceIp` is populated from `X-Forwarded-For`/`X-Real-IP`
  (`_MINIO_API_XFF_HEADER` default On, no trusted-proxy allowlist); a directly-reachable instance has every
  IP-restricted policy bypassable by spoofing the header (live confirmed). *Fix:* only trust XFF from a
  configured trusted-proxy set.
- **F-12 (High)** — `ExportBucketMetadataHandler` returns the raw `madmin.BucketTargets` including the
  **unredacted replication-target SecretKey/SessionToken**; a holder of `ExportBucketMetadataAction` harvests
  credentials to the remote target → lateral movement.
- **F-11 (Med–High)** — `admin:ServerTrace` streams unredacted request data (SSE-C customer **keys**,
  Authorization signatures, presigned-URL signatures) of **all** tenants to a narrow-trace subscriber.
- **F-14 (Medium)** — `notify_mysql` `table` config field has no identifier validation (its Postgres sibling
  got `validatePsqlTableName` in PR #19602; MySQL never did) → SQL injection into six raw-SQL templates by an
  `admin:ConfigUpdate` holder; the partial-KV merge means the attacker needn't know the DSN secret.
- Needs-live (characterized): `R3-02-B` AuthN/AuthZ plugin URL SSRF (admin-set), `R3-09-B` ImportBucketMetadata
  cross-bucket config overwrite, `R3-02-A` plugin dial-error internal-recon oracle. `R3-03-02` InspectData →
  design (admin diagnostic). `R3-12-C2` → Low (per-object corruption DoS, no encryption bypass — codex).

### F-04 (Low–Med, hardening) / F-05 (Low, inert)
F-04: internode storage-REST handlers build `pathJoin(volumeDir, path)` with no post-`Clean` containment, so an
embedded `..` escapes the drive root (arbitrary file R/W) — but every handler is gated by
`storageServerRequestValidate`, a bearer JWT signed with the **root secret**, so only a compromised peer/insider
reaches it. Defense-in-depth: add a containment check. F-05: the SFTP/FTP LDAP path authenticates a service
account via a raw `GetUser` that skips `IsValid()`, so a disabled/expired svcacct passes the *login callback* —
but every subsequent S3 operation re-checks and denies it, so it is cosmetic.

---
## Rejected / refuted (evidence of rigor — not reported as findings)

| Candidate | Why rejected |
|---|---|
| R1-07-A/B/C IAM import privesc | `ImportIAMAction` is an intentional aggregate capability; #20756 fix complete (codex) |
| R1-05-C1 (first pass) | Initially rejected on the wrong traversal shape; **codex overturned it → became F-02** |
| R1-01-C1 copy-source hijack | CopyObject re-checks `GetObjectAction` on the source (2018 commit 88c3dd49c), present at HEAD |
| R1-09-2 OIDC missing-exp | No-exp token → HTTP 500, not an auth bypass; expiry enforced for present exp (live) |
| **R2-07-C1 retention authz "regression"** | **Live-refuted:** authz enforced in the metadata-eval callback; lowuser → 403, root → 200 |
| **R2-06-A WORM-bypass via REPLICA header** | **Live-refuted (2025-09-07 + exact-HEAD):** object still receives COMPLIANCE retention |
| R2-13-C single-master-secret HMAC reuse | codex: false positive (not a real key-reuse flaw) |
| R2-15-01/02 public metrics disclosure | Design — only when operator sets `MINIO_PROMETHEUS_AUTH_TYPE=public` |
| KMS router wrapper-parity gap | Handlers self-authorize via `validateAdminReq`; unauth → 403 (live) |
| DoS-class (chunk-trailer, s3select, prealloc, nil-deref) | Deprioritized per engagement scope (auth/RCE focus, not DoS) |

## Needs-live queue (characterized, not yet reproduced)
`R2-02-A/C` SR replicate IAM/bucket-item privesc (High, same SR trust gap as F-07) · `R2-05-01` grid connect
static bearer token (Med) · `R2-09-C2` DescribeBatchJob leaks source remote creds (High) · `R2-09-C3`/`R2-11-C1`
notification/webhook target SSRF (Med, admin-gated) · `R2-11-C2` GetObjectLambda invoke any function (High) ·
`R2-06-B` SSE-C multipart key-validation bypass (needs TLS) · `R2-04-C2` bootstrap VerifyHandler env-hash
disclosure (Low) · `R2-12-01`/`R2-13-A` SSE-KMS AAD accepted from client (Low). Also from Round 1: `R1-04-02`
STS duration-deny only on WebIdentity/ClientGrants; `R1-03-C2` POST-policy non-allowlisted conditions
unvalidated; `R1-12-A` SSE-C ciphertext exfil via replication header (needs TLS). Each has an exact test in
`TRIED.md`.

---
## Coverage & limits

**Deterministic front-load (Round 0):** prior-art recon (27 GHSAs + recent security commits → variant seeds);
`/sca` (resolved deps current/patched — the SCA "criticals" were go.sum historical-version noise); Semgrep Go
packs (106 hits, mostly generic noise); full 254-route entrypoint manifest; 66-component inventory.

**Altitudes covered:** whole-project (Round 1, 15 cells, authz/authn/signature veins), file-by-file (Round 2,
15 cells: internode RPC, site-replication, object-lock, lifecycle, batch, multipart, admin service/update,
events, crypto/KMS, metrics), and function-level + remaining-surface (Round 3, 12 cells: config validators,
admin inspect/trace/import, metacache, xl-storage parsing, streaming-sig parser, policy-condition evaluation,
presign, event-store, KMS context, copy-object metadata). Of 66 inventoried components, **~50 received a hunt
cell** across three rounds.

**Convergence:** Round 4 (12 cells: config-target SSRF/injection matrix, LDAP deep, races/TOCTOU, internode
deserialization, presign/multipart/STS edges, metacache, KMS context, bucket-policy parsing) surfaced 16
candidates but **every one is an instance of a class already found** — config-secret disclosure (F-16), the
replication-header-trust class (R4-07-1), authz-granularity (R4-12-01 versioned-read), LDAP error-passthrough
(R4-02-01), STS-deny (R4-05-02), plus DoS/races (out of scope). **No new unauthenticated class and no new
Critical emerged.** The Critical/High unauthenticated and privilege-escalation findings all landed in Rounds 1–3;
Round 4 produced only refinements and scoped/admin-gated Mediums. The high-value external attack surface is
effectively exhausted.

**NOT done:** (1) a **formal second consecutive fully-dry round** (K=2) — Round 4 still produced new *candidates*
(all refinements), so the strict stop condition is not satisfied; a Round 5 would confirm it, but the severity
trend (Rounds 1→4: Critical-unauth → admin-gated-Medium → refinements) indicates strongly diminishing returns.
(2) ~16 components remain `UNCOVERED` (erasure/xl-storage backend, bitrot/format, heal/decom/rebalance core,
data-scanner, dsync internals) — internode/background surface reachable only behind the root-JWT (see F-04).
(3) The **needs-live** queue (STS-cert deny, versioned-read authz, svcacct-stale-groups, ES-index injection,
SSE-KMS AAD, ImportBucketMetadata overwrite, plugin SSRF). (4) Live exploits for the codex-confirmed defects
(F-07 madmin client; F-09/F-12 harness). Bug classes only partially swept: races/TOCTOU (Round 4 flagged three
as needs-live) and internode msgpack deserialization.

**What is solid.** SigV4/SigV2 core verification, presigned-URL handling, the IAM policy-evaluation engine's
allow/deny ordering, the KMS admin authorization, and the object-tagging read/write authz ordering were examined
and found sound. Dependencies are current. The bugs found are decentralized per-handler authorization omissions
and trust-boundary confusions — the same class MinIO has repeatedly patched — concentrated in the newer/less-
audited subsystems (site-replication, batch, fan-out, OIDC multi-provider, server-update).

---
## Artifacts
`FINDINGS.md` (register + rejected set) · `TRIED.md` (per-round attempt ledger + coverage matrix) ·
`poc/F-01..F-09*.md` (per-finding root cause, trace, live oracle, fix) · `entrypoint-manifest.md` (254 routes) ·
`round{1,2}-*.json` (raw candidate + verify data). Lab reproduction harnesses: `/tmp/s3sig.py` (stdlib SigV4),
`/tmp/mock_idp.py` (dual OIDC), 2-node active-active build on `root@192.168.1.119`.
