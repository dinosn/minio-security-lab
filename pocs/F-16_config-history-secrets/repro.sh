#!/usr/bin/env bash
# F-16 — `config history` returns historically-set secrets in PLAINTEXT, while the live
# `config get` redacts them.
# Prereq: setup/01-single-node.sh
set -euo pipefail
. "$(dirname "$0")/../../setup/env.sh"
T=${1:-$S1}

echo "=== set a config value with a distinctive secret, twice (creates a history entry) ==="
mcsh '
mc alias set L '"$T"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc admin config set L notify_webhook:t1 endpoint="http://127.0.0.1:9999/hook" auth_token="SECRETWEBHOOKTOKEN123" queue_dir="/tmp/q1" >/dev/null 2>&1
mc admin config set L notify_webhook:t1 endpoint="http://127.0.0.1:9999/hook" auth_token="SECRETWEBHOOKTOKEN123" queue_dir="/tmp/q2" >/dev/null 2>&1
'
echo "=== current config get (should REDACT the secret) ==="
mcsh 'mc alias set L '"$T"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1; mc admin config get L notify_webhook:t1' | grep -oiE 'auth_token=[^ ]*' | head -1 || echo "  (auth_token not shown / redacted in config get)"
echo "=== config HISTORY (F-16: leaks it in plaintext) ==="
mcsh 'mc alias set L '"$T"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1; mc admin config history L' | grep -oiE 'auth_token=[^ ]+|client_secret=[^ ]+' | sort | uniq -c
echo
echo "VULNERABLE if: config get shows the token redacted/absent but config history prints it in plaintext."
