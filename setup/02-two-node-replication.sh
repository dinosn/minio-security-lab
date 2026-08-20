#!/usr/bin/env bash
# Two single-drive MinIO nodes with A->B active replication on bucket `vault`, for F-01.
# Uses the exact-HEAD binary if present (/tmp/minio-head-bin), else the image.
set -euo pipefail
. "$(dirname "$0")/env.sh"

start_node() { # name port consoleport datadir
  if [ -x /tmp/minio-head-bin ]; then
    pkill -f "minio-head-bin server $4" 2>/dev/null || true; sleep 1; rm -rf "$4"; mkdir -p "$4"
    MINIO_ROOT_USER="$ROOT_USER" MINIO_ROOT_PASSWORD="$ROOT_PASS" \
      nohup /tmp/minio-head-bin server "$4" --address ":$2" --console-address ":$3" >/tmp/$1.log 2>&1 &
  else
    docker rm -f "$1" >/dev/null 2>&1 || true
    docker run -d --name "$1" --network host \
      -e MINIO_ROOT_USER="$ROOT_USER" -e MINIO_ROOT_PASSWORD="$ROOT_PASS" \
      "$MINIO_IMAGE" server "$4" --address ":$2" --console-address ":$3" >/dev/null
  fi
}
start_node nodeA 19000 19010 /tmp/dataA
start_node nodeB 19001 19011 /tmp/dataB
sleep 6
echo "[2node] A health=$(curl -s -o /dev/null -w '%{http_code}' $NODE_A/minio/health/live) B=$(curl -s -o /dev/null -w '%{http_code}' $NODE_B/minio/health/live)"

mcsh '
mc alias set A '"$NODE_A"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc alias set B '"$NODE_B"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc mb -p A/vault B/vault 2>&1 | tail -2
mc version enable A/vault; mc version enable B/vault
# A replicates to B (one-way is enough: it makes getProxyTargets(A) non-empty and keeps
# an object PUT only on B absent from A, which is the F-01 precondition).
mc replicate add A/vault --remote-bucket http://'"$ROOT_USER"':'"$ROOT_PASS"'@localhost:19001/vault --priority 1 2>&1 | tail -1
'
echo "[2node] ready. A=vault(has A->B replication target), B=vault"
