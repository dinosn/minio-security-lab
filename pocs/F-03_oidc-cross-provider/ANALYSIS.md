# F-03 — OIDC cross-provider signature confusion → admin takeover (missing issuer validation + unscoped key map)

**Severity:** High (confirmed) / Critical (potential — admin takeover) · **Disposition:** CONFIRMED (LIVE, admin takeover)
**Component:** auth-identity-openid · **CWE-347 Improper Verification of Cryptographic Signature / CWE-287**
**Target:** minio @ 7aac2a2c; reproduced on exact-HEAD build (node A :19000) with two mock OIDC providers

## LIVE PROOF (dual mock IdP, exact-HEAD)
Setup: provider A (kid=keyA, client_id=clientA, role_policy=**consoleAdmin**, roleArn `…jbKlmGQBAA…`), provider B
(kid=keyB, client_id=clientB, role_policy=readonly). Both JWKS loaded into MinIO's Config-wide key map.
```
ATTACK: token signed by B's PRIVATE KEY (kid=keyB), iss=http://…:8802 (B), aud=clientA (A's client_id), sub=attacker
        -> POST AssumeRoleWithWebIdentity RoleArn=<A's admin roleArn>
   => HTTP 200; session-token claims: {iss:":8802"(B), aud:clientA, roleArn:"…jbKlmGQBAA…"(A/consoleAdmin), sub:attacker}
BEHAVIORAL (forged creds via mc):  mc admin info -> "● 127.0.0.1:19000" (consoleAdmin op OK);  mc mb -> "Bucket created successfully"
CONTROL: same B-signed token with aud=clientB (B's own aud) on A's roleArn -> HTTP 400 InvalidParameterValue (rejected)
```
So a token **signed by provider B's key** with **B's issuer** obtained **provider A's admin role** — MinIO verified
the signature with B's key from the shared `kid` map, matched only `aud`, ignored `iss`, and issued admin creds.
Oracle class: **policy-bypass / authorization** — forged creds perform consoleAdmin-only operations.


## Root cause
In `internal/config/identity/openid`, the JWKS public keys are held in a single Config-wide
`publicKeys{pkMap}` instance (jwt.go:37-42, openid.go ~170), populated by **every** configured OIDC
provider keyed by `kid` alone (openid.go:392). `Config.Validate`'s `keyFuncCallback` resolves the
verification key via `pubKeys.get(kid)` (jwt.go:151) with **no scoping to the provider/role-ARN being
assumed**. The STS `AssumeRoleWithWebIdentity` path binds the requested role ARN to provider A and checks
A's `client_id` against the token's `aud`/`azp` (jwt.go:198) — but it **never validates the `iss` (issuer)
claim** and never restricts key selection to provider A's JWKS.

## Consequence
In a deployment with ≥2 OIDC providers, an attacker who controls (or can obtain a signed token from)
a less-trusted provider B can mint a JWT that carries **provider A's audience** and the **role ARN bound
to A**, signed with B's key (whose `kid` is already in the shared map). MinIO verifies it with B's key,
matches A's `client_id`, and issues STS credentials with **A's role policy** — cross-trust-boundary role
impersonation / privilege escalation.

## Gate (why needs-live)
Requires: multiple enabled OIDC providers; attacker influence over one provider's signing key/JWKS (or the
ability to make B issue a token with A's `aud`); with `claim_userinfo=on`, additionally a valid A access
token. STS issuance itself is public. Not default (single-provider deployments are unaffected), but a
realistic enterprise multi-IdP config.

## Exact live test
1. Configure two OIDC providers A (trusted, bound to role ARN `arn:...:role/admin`) and B (attacker-controlled).
2. Mint a JWT signed by B's key with `aud`=A's client_id, `sub`/claims mapping to A's admin role, and the
   role ARN of A in the AssumeRoleWithWebIdentity request.
3. Expected vulnerable: STS returns credentials with A's (admin) policy. Expected safe (if `iss` were
   validated / key scoped to A): `InvalidParameterValue`/signature failure.

## Fix
Validate `iss` against the provider bound to the requested role ARN, and scope JWKS key selection to that
provider's key set (per-provider `pubKeys`), not a Config-wide `kid` map.

## Confirmations
generator(Sonnet,raw) + verify(Sonnet,raw) + **codex(OpenAI cross-vendor): CONFIRMED HIGH** (decisive:
jwt.go:151 unscoped key lookup; jwt.go:198 checks aud but not iss; openid.go:392 shared population). Live
exploit pending a 2-IdP lab.
