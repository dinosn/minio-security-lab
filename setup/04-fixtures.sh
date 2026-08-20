#!/usr/bin/env bash
# Common test fixtures on the single node (:9000): tenants, a low-priv user, and a
# positive-control policy check. Used by several PoCs.
set -euo pipefail
. "$(dirname "$0")/env.sh"

mcsh '
mc alias set lab '"$S1"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc mb -p lab/tenant-a lab/tenant-b >/dev/null 2>&1
printf "hello-from-tenant-a\n" | mc pipe lab/tenant-a/secret.txt >/dev/null 2>&1
cat > /tmp/ro.json <<POL
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::tenant-a","arn:aws:s3:::tenant-a/*"]}]}
POL
mc admin policy create lab readonly-a /tmp/ro.json 2>&1 | tail -1
mc admin user add lab lowuser lowpass12345 2>&1 | tail -1
mc admin policy attach lab readonly-a --user lowuser 2>&1 | tail -1
mc alias set low '"$S1"' lowuser lowpass12345 >/dev/null 2>&1
echo "=== positive control (baseline authz enforced) ==="
printf "  [ALLOW] low read tenant-a/secret.txt : "; mc cat low/tenant-a/secret.txt 2>&1 | tail -1
printf "  [DENY ] low read tenant-b            : "; mc cat low/tenant-b/secret.txt 2>&1 | tail -1
'
echo "[fixtures] root=$ROOT_USER/$ROOT_PASS  low=lowuser/lowpass12345 (readonly tenant-a)"
