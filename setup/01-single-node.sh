#!/usr/bin/env bash
# Single-node MinIO on :9000 for F-10, F-15, F-16, F-02, F-06, F-08, F-11, F-12, F-14.
set -euo pipefail
. "$(dirname "$0")/env.sh"

docker rm -f minio-lab >/dev/null 2>&1 || true
docker run -d --name minio-lab --network host \
  -e MINIO_ROOT_USER="$ROOT_USER" -e MINIO_ROOT_PASSWORD="$ROOT_PASS" \
  "$MINIO_IMAGE" server /data --console-address :9001 >/dev/null
sleep 5
code=$(curl -s -o /dev/null -w '%{http_code}' "$S1/minio/health/live")
echo "[single] health=$code  image=$MINIO_IMAGE"
mc alias set lab "$S1" "$ROOT_USER" "$ROOT_PASS" >/dev/null 2>&1
echo "[single] ready. Alias 'lab' -> $S1"
