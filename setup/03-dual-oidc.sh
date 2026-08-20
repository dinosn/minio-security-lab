#!/usr/bin/env bash
# Dual mock OIDC providers + node A configured with both, for F-03.
# Requires: python3 with `cryptography` and `PyJWT` (pip install cryptography PyJWT).
# Provider A (kid=keyA, client_id=clientA) -> role_policy=consoleAdmin  (the "admin" IdP)
# Provider B (kid=keyB, client_id=clientB) -> role_policy=readonly      (the "low-trust" IdP)
set -euo pipefail
. "$(dirname "$0")/env.sh"
HARNESS="$(cd "$(dirname "$0")/../harness" && pwd)"

# 1) start the dual mock IdP (A :8801, B :8802)
pkill -f "mock_idp.py serve" 2>/dev/null || true
rm -f /tmp/idp_*.pem
nohup python3 "$HARNESS/mock_idp.py" serve >/tmp/idp.log 2>&1 &
sleep 2
curl -sf "http://127.0.0.1:8801/jwks" >/dev/null && echo "[oidc] provider A up (:8801)"
curl -sf "http://127.0.0.1:8802/jwks" >/dev/null && echo "[oidc] provider B up (:8802)"

# 2) node A must be running (setup/02 or a single node on :19000). Configure both providers.
mcsh '
mc alias set A '"$NODE_A"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc admin config set A identity_openid:pa config_url="http://127.0.0.1:8801/.well-known/openid-configuration" client_id="clientA" client_secret="secretA" role_policy="consoleAdmin" scopes="openid" 2>&1 | tail -1
mc admin config set A identity_openid:pb config_url="http://127.0.0.1:8802/.well-known/openid-configuration" client_id="clientB" client_secret="secretB" role_policy="readonly" scopes="openid" 2>&1 | tail -1
'
# 3) restart node A to load OIDC and print the role ARNs
if [ -x /tmp/minio-head-bin ]; then
  pkill -f "minio-head-bin server /tmp/dataA" 2>/dev/null || true; sleep 2
  MINIO_ROOT_USER="$ROOT_USER" MINIO_ROOT_PASSWORD="$ROOT_PASS" \
    nohup /tmp/minio-head-bin server /tmp/dataA --address :19000 --console-address :19010 >/tmp/nodeA.log 2>&1 &
  sleep 6
  echo "[oidc] role ARNs:"; grep -ioE 'arn:minio:iam:::role/[A-Za-z0-9_-]+' /tmp/nodeA.log | sort -u
else
  docker restart nodeA >/dev/null; sleep 6
  echo "[oidc] role ARNs:"; docker logs nodeA 2>&1 | grep -ioE 'arn:minio:iam:::role/[A-Za-z0-9_-]+' | sort -u
fi
echo "[oidc] Map ARN->provider: the ARN that a provider-A token (aud=clientA) can assume is the consoleAdmin role."
