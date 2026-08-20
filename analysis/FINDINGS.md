# FINDINGS.md — MinIO loop-hunt confirmed/pending findings register

Target: minio @ 7aac2a2c · Engagement minio-1. Exclusion set for dedup (this engagement only).

Disposition ∈ {confirmed, needs-live-validation, corrected, rejected}. Only survivors past
generate→judge→(cross-vendor codex)→live-verify land here. Rejected set tracked at bottom.

| ID | Severity (conf/pot) | Component | Root cause (fn@file) | Disposition | Receipt |
|---|---|---|---|---|---|
| F-01 | Medium/High | s3api-object-handlers | DeleteObjectTaggingHandler@cmd/object-handlers.go:3292 omits pre-proxy auth; proxyTaggingToRepTarget@3326 deletes peer tags with root repl creds before checkRequestAuthType@3358 | **CONFIRMED** (live oracle) | poc/F-01-delete-tagging-authbypass.md · codex CONFIRMED HIGH · 204-vs-403 differential + tag-removal · DIRTY_SWEEP: only proxy path missing auth |
| F-02 | High/High | auth-iam-store | NewServiceAccount@cmd/iam.go:1063 validates access key length-only (IsAccessKeyValid); getUserIdentityPath pathJoin/path.Clean collapses `../users/<victim>` onto victim identity object → any authed user destroys any account | **CONFIRMED** (live oracle, persists across reload) | poc/F-02-svcacct-key-traversal.md · codex CONFIRMED High · non-admin destroyed victimuser2 across reload · DIRTY_SWEEP: svcacct key = only low-priv sink (STS server-gen safe; group/policy admin-gated) |
| F-03 | High/Critical | auth-identity-openid | keyFuncCallback@jwt.go:151 resolves JWKS key by kid across a Config-wide shared map + AssumeRoleWithWebIdentity checks aud but not iss (jwt.go:198) → cross-provider signature confusion → admin takeover | **CONFIRMED** (LIVE dual-IdP, admin takeover) | poc/F-03-oidc-cross-provider-key.md · codex CONFIRMED HIGH · LIVE: B-key-signed token w/ A audience → A's consoleAdmin role; forged creds run `mc admin info`/`mc mb`; aud-mismatch control rejected |
| F-04 | Low-Med | internode-storage-rest | getVolDir/checkPathLength@xl-storage.go reject only exact ".."; pathJoin(path.Clean) w/o containment → arbitrary file R/W, but gated behind internode root-JWT (storageServerRequestValidate) | needs-live (compromised-peer only) | codex CONFIRMED HIGH-code/gated · xl-storage.go:1888, storage-rest-server.go:128 · insider/post-compromise only → hardening |
| F-05 | Low | sftp-server/ftp | getAccountWithClaims@iam.go:1334 uses raw GetUser (skips IsValid) → disabled/expired svcacct passes SFTP/FTP login callback (LDAP mode) | CONFIRMED (inert) | codex CONFIRMED narrowly LOW · subsequent S3 ops still reject disabled cred → cosmetic login only |
| F-06 | High/Critical | admin-api-service-update | ServerUpdateHandler@cmd/admin-handlers.go passes attacker `updateURL` to downloadReleaseURL (no RFC1918/link-local/IMDS filter); parseReleaseData reflects full fetched body into JSON error | **CONFIRMED** (live) | poc/F-06-serverupdate-ssrf-reflection.md · LIVE: updateURL=internal → body `Unknown release data \`SECRET…\`` reflected; IMDS dialed; loopback blocked · verify wf_8bf5ba19 live_confirmed · gate admin:ServerUpdate |

| F-07 | Critical | admin-api-site-replication | SRPeerJoin@cmd/admin-handlers-site-replication.go:80 (gate admin:SiteReplicationAdd only, no peer/shared-secret) → PeerJoinReq feeds attacker SvcAcctParent+key+secret to NewServiceAccount (site-replication.go:626); parent=root ⇒ inherits full admin | **CONFIRMED-DEFECT** (codex CRITICAL) / live-exploit pending madmin-encrypted body | codex: gate FAIL, root-parent inheritance iam.go:1103/2214; reachable pre-SR-config; deployment ID obtainable unauth. **Privesc to root.** Exact test recorded. |
| F-08 | High | batch-jobs | StartBatchJob@cmd/batch-handlers.go:1749 gated only by admin:StartBatchJob; Validate checks bucket existence not submitter policy; job reads source with global worker context (batch-handlers.go:1800/2056) not caller identity | **CONFIRMED** (live oracle) | poc/F-08 · codex HIGH + LIVE: batchuser (no read on secret-bkt, control=Insufficient permissions) submits replicate job → exfil-bkt/private.txt="TOP-SECRET-BATCH-EXFIL". Calibrates codex Round-2 as reliable. |
| F-09 | High | s3api-postpolicyform | PostPolicyBucketHandler fan-out: signature+POST-policy+s3:PutObjectFanOut checked only vs outer Key (bucket-handlers.go:1136/1159); fanout-list keys omitted from checkPostPolicy → each req.Key → PutObject unchecked (post-policy-fan-out.go:113) | **CONFIRMED-DEFECT** (codex HIGH) | codex: bucket-scoped (NOT cross-bucket); arbitrary key create/overwrite in the request bucket, bypassing prefix policy. |

| F-10 | High | bucket-policy / auth | getConditionValues@cmd/bucket-policy.go sets aws:SourceIp from GetSourceIPRaw→GetSourceIPFromHeaders (X-Forwarded-For/X-Real-IP, `_MINIO_API_XFF_HEADER` defaults On, no trusted-proxy allowlist) → client spoofs source IP to satisfy IP-conditioned policy | **CONFIRMED** (live) | LIVE: ip-only policy (allow 10.99.99.0/24), real-IP GET→403; XFF=10.99.99.50→200; X-Real-IP→200; XFF=8.8.8.8 control→403. Default-on. (R3-07-01: getConditionValues also merges ALL headers+query into condition map — mechanism.) |

| F-11 | Medium-High | admin trace | TraceHandler@cmd/admin-handlers.go (gate admin:ServerTrace only) streams unredacted request data incl. SSE-C customer keys, Authorization sigs, presigned signatures of ALL tenants to the subscriber | CONFIRMED-DEFECT (verify live) | narrow ServerTrace admin captures other tenants' SSE-C keys + presigned sigs. round3-verify live_confirmed High. |
| F-12 | High | admin-api-site-replication | ExportBucketMetadataHandler bucketTargetsFile case returns raw madmin.BucketTargets incl. unredacted replication-target SecretKey/SessionToken (admin-bucket-handlers.go) | CONFIRMED-DEFECT (verify live) | ExportBucketMetadataAction holder extracts remote-target creds → lateral movement. round3-verify live_confirmed High. |
| F-13 | Low | s3api-object-multipart-copy | CopyObject REPLACE injects reserved X-Minio-Replication-SSE-Sealed-Key alias → copied object becomes unreadable | REJECTED-as-high / Low corruption-DoS | codex: NO encryption bypass/leak (server metadata overwrites; ErrEncryptedObject on GET). Per-object DoS, needs GetObject+PutObject rights. DoS-class → deprioritized. |
| F-15 | High | bucket-policy / auth | getConditionValues@cmd/bucket-policy.go:179 merges ALL request headers+query into the condition map; policy engine canonicalizes key names first (value.go:29) so a header shadows the server value → aws:username / SecureTransport / s3:x-amz-* conditions forgeable | **CONFIRMED** (live) | codex CONFIRMED High (broader than F-10). LIVE: policy allow-if aws:username=backup-reader; anon GET→403; anon GET+`Username: backup-reader`→200; control `Username: wronguser`→403. **Unauthenticated** condition bypass. |
| F-14 | Medium | config-subsystem | MySQLArgs.Validate@internal/event/target/mysql.go checks Table non-empty only (no validatePsqlTableName parity); table name → fmt.Sprintf into raw SQL (executeStmts) → SQLi | CONFIRMED-DEFECT (verify, MySQL-vs-Postgres differential) | admin:ConfigUpdate gated; partial-KV-merge means attacker needn't know DSN secret. Postgres sibling validates (PR#19602), MySQL never did. |

| F-16 | High | config-subsystem | listServerConfigHistory@cmd/config.go (ListConfigHistoryKVHandler) does not redact secret KV values, unlike current get-config-kv → config history returns all historically-set secrets in plaintext | **CONFIRMED** (live) | LIVE: `config get identity_openid:pa` redacts client_secret; `config history` shows `client_secret=secretA`/`secretB` plaintext. Narrow config-history admin harvests all IdP/webhook/replication/LDAP/KMS secrets ever set. |

### Round 4 — refinements of known classes (loop converging; no new unauth/Critical class)
- R4-07-1 (High) replication-header trust in multipart (NewMultipart/PutPart/Complete honor client X-Minio-Source-Replication-Request) — same class as F-01/R1-12-A/R3-12-C2; needs-live.
- R4-12-01 (High corrected) versioned reads (GET/HEAD/copy-source ?versionId) authorized with s3:GetObject not s3:GetObjectVersion → GetObject-only user reads old versions. Authz-granularity; needs-live.
- R4-02-01 (Medium) unauth LDAP username-enum + DN disclosure via AssumeRoleWithLDAPIdentity error passthrough (GHSA-jv87 class); same as R3-02-A recon-oracle.
- R4-03-01 (Med-High) svcacct Groups snapshot frozen at creation (stale-group privilege); R4-05-02 STS Cert/CustomToken skip Deny conditions (R1-04-02 class); R4-10-B restoreId path-traversal (Low). All needs-live.
- DoS-class (deprioritized): R4-04-02/03 (Content-Length/slice alloc), R4-11-2 (unbounded wildcard.Match). Races R4-03-02/03 needs-live. R4-01-B ES index injection needs-live Low. R4-09-1 SSE-KMS AAD (recurring, Low).

**REJECTED (Round 2):** R2-07-C1 (gen/verify rated Critical "any zero-perm user sets retention") → **REJECTED by LIVE oracle**: lowuser PUT ?retention → 403 AccessDenied, root → 200. Authz enforced in EvalMetadataFn→enforceRetentionBypassForPut→isPutRetentionAllowed→IsAllowed(PutObjectRetentionAction). Both generator AND the code-only verify agent missed the deferred authz; live test is authoritative. R2-07-C2 (governance-shorten) same cell — authz present, likely FP. R2-12-02, R2-13-C → verify FALSE_POSITIVE. R2-15-01/02 public-metrics → design (only when operator sets PROMETHEUS_AUTH_TYPE=public).

---
## REJECTED (this engagement) — with observed reason (dedup guard)
| ID | Claim | Observed refutation | Cross-vendor |
|---|---|---|---|

---
## NEEDS-LIVE-VALIDATION queue
| ID | Potential sev | Exact safe test | Status |
|---|---|---|---|
