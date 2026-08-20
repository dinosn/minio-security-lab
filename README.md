# MinIO Security Review Lab — commit `7aac2a2c`

Reproduction environment and analysis notes for a defensive security review of
[MinIO](https://github.com/minio/minio) at commit `7aac2a2c5b7c882e68c1ce017d8256be2feea27f`
(≈ RELEASE.2025-10-15 + 11 commits). Purpose: coordinated disclosure to the vendor and regression/patch
verification. The issues are authorization and trust-boundary weaknesses; each was found by source review and,
where marked **Live**, verified against a MinIO instance built from that commit using a pass/fail check.

> Private research repository for authorized testing only. Do not point these scripts at infrastructure you do
> not own or operate. Intended for vendor coordination, not public release.

## Issue register

| ID | Sev | Summary | Component | Requires | Verified | Notes |
|----|-----|---------|-----------|----------|----------|-------|
| F-03 | High→Crit | OIDC key selection is not scoped per provider and the issuer is not checked, so a token from one configured provider is accepted for another provider's role | identity/openid | 2+ OIDC providers, one key controlled | Live | [pocs/F-03](pocs/F-03_oidc-cross-provider/) |
| F-07 | Crit | Site-replication peer-join accepts an attacker-chosen service-account parent with no peer authentication | site-replication | scoped admin action | review | [pocs/F-07-08-09](pocs/F-07-08-09_round2-highs/) |
| F-15 | High | Request headers are merged into the policy-condition context and shadow server-derived keys (`aws:username` etc.) | bucket-policy/auth | none (anonymous) | Live | [pocs/F-15](pocs/F-15_condition-shadow/) |
| F-02 | High | Service-account access keys are not validated for path separators before use as a storage key, overwriting another account's identity object | iam-store | any authenticated user | Live | [pocs/F-02](pocs/F-02_svcacct-key-traversal/) |
| F-06 | High→Crit | The server-update endpoint fetches an operator-supplied URL with no destination filtering and reflects the response body in its error | admin service-update | scoped admin action | Live | [pocs/F-06](pocs/F-06_serverupdate-ssrf/) |
| F-08 | High | Batch jobs read the source bucket with the server's own authority rather than the submitter's policy | batch-jobs | scoped admin action | Live | [pocs/F-08](pocs/F-08_batch-exfil/) |
| F-10 | High | `aws:SourceIp` is populated from client `X-Forwarded-For`/`X-Real-IP` with no trusted-proxy allowlist (default-on) | bucket-policy/auth | none (anonymous) | Live | [pocs/F-10](pocs/F-10_sourceip-xff/) |
| F-16 | High | `config history` returns previously-configured secret values unredacted, unlike the live `config get` | config-subsystem | config-history read | Live | [pocs/F-16](pocs/F-16_config-history-secrets/) |
| F-01 | Med→High | The delete-object-tagging replication-proxy branch runs before the authorization check | object-handlers | none (anonymous) | Live | [pocs/F-01](pocs/F-01_tag-deletion/) |
| F-12 | High | Bucket-metadata export returns replication-target credentials unredacted | admin bucket-meta | scoped admin action | review | [analysis/FINDINGS.md](analysis/FINDINGS.md) |
| F-11 | Med-High | The server-trace stream includes request secrets (customer encryption keys, signatures) of all tenants | admin trace | scoped admin action | review | [analysis/FINDINGS.md](analysis/FINDINGS.md) |
| F-09 | High | Multi-object fan-out upload authorizes only the outer key; per-entry keys are unchecked (same bucket) | postpolicyform | fan-out uploader | review | [pocs/F-07-08-09](pocs/F-07-08-09_round2-highs/) |
| F-14 | Med | The MySQL notification-target table name is not validated, unlike the PostgreSQL sibling | config/event-target | scoped admin action | review | [analysis/FINDINGS.md](analysis/FINDINGS.md) |
| F-04 | Low-Med | Internode storage path handling lacks a containment check (gated behind the internode root token) | storage-rest | compromised peer | review | [analysis/FINDINGS.md](analysis/FINDINGS.md) |
| F-05 | Low | A disabled service account passes the SFTP/FTP login callback but is still denied by the S3 layer | sftp/ftp | knows old secret | review | [analysis/FINDINGS.md](analysis/FINDINGS.md) |
| F-13 | Low | CopyObject metadata-replace can set reserved keys, corrupting a single object (availability only) | object-copy | read+write rights | review | [analysis/FINDINGS.md](analysis/FINDINGS.md) |

**Verified:** *Live* = pass/fail check reproduced on the running server (script in `pocs/`). *review* = confirmed
by independent code review (OpenAI/codex cross-vendor and a from-raw verifier); each carries an exact test in
[`analysis/FINDINGS.md`](analysis/FINDINGS.md) but is not scripted here (some need a Go client or a specific
multi-service setup). Full root cause, data-flow trace, and suggested fix for every item are in
[`analysis/`](analysis/) and each finding's `ANALYSIS.md`.

## Lab setup

Requirements: **Docker**, `python3` (plus `pip install cryptography PyJWT` for the OIDC check only). Go 1.24+ is
only needed for the exact-commit binary. No local `minio`/`mc` install — everything runs in containers.

```bash
. setup/env.sh                       # endpoints, credentials, mc helper (source it)
bash setup/00-build-head.sh          # optional: build the exact-commit binary -> /tmp/minio-head-bin

bash setup/01-single-node.sh         # MinIO on :9000  (F-02,06,08,10,11,12,14,15,16)
bash setup/04-fixtures.sh            # tenants + a low-privilege user + a positive control

bash setup/02-two-node-replication.sh   # nodes A:19000 / B:19001, active replication (F-01)
bash setup/03-dual-oidc.sh               # two mock OIDC providers on node A       (F-03)
```

## Running a check

```bash
bash pocs/F-15_condition-shadow/repro.sh
bash pocs/F-10_sourceip-xff/repro.sh
bash pocs/F-01_tag-deletion/repro.sh            # needs setup/02
bash pocs/F-03_oidc-cross-provider/repro.sh     # needs setup/03
bash pocs/F-02_svcacct-key-traversal/repro.sh
bash pocs/F-06_serverupdate-ssrf/repro.sh
bash pocs/F-08_batch-exfil/repro.sh
bash pocs/F-16_config-history-secrets/repro.sh
```

Each `repro.sh` prints a **VULNERABLE if:** line stating the expected pass/fail signal.

## Layout

```
setup/     lab bring-up (single node, 2-node replication, dual OIDC, fixtures)
harness/   s3sig.py   — stdlib AWS SigV4 signer (sign a request, then attach extra headers)
           mock_idp.py — dual mock OIDC provider + RS256 token minter (self-signed test keys)
pocs/      per finding: ANALYSIS.md (root cause / trace / fix) + repro.sh
analysis/  REPORT.md (engagement report), FINDINGS.md (register incl. the rejected set),
           entrypoint-manifest.md (route map)
```

## Method

Multi-altitude source review (whole-project → file → function) with an isolated
generate → judge → independent-verify pipeline, cross-vendor adjudication, and live checks on a lab-built binary.
About 90 candidates were triaged and roughly 55 set aside as intended behavior, already-patched, or false
positives — four of them ruled out specifically by live testing after passing static review. See
[`analysis/REPORT.md`](analysis/REPORT.md) for coverage, the set-aside list, and remaining work.
