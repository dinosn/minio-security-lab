#!/usr/bin/env bash
# Build the EXACT audited HEAD binary (7aac2a2c) for precise-fidelity reproduction.
# Requires: git + Go 1.24+. Produces /tmp/minio-head-bin.
# (For most PoCs the official `minio/minio` image is close enough; use this when
#  you want byte-for-byte fidelity with the audited commit.)
set -euo pipefail
. "$(dirname "$0")/env.sh"

cd /tmp
rm -rf minio-head
echo "[build] cloning minio @ $COMMIT ..."
git clone -q https://github.com/minio/minio.git minio-head
cd minio-head
git checkout -q "$COMMIT"
echo "[build] go build (CGO off) ..."
CGO_ENABLED=0 go build -o /tmp/minio-head-bin .
/tmp/minio-head-bin --version | head -2
echo "[build] OK -> /tmp/minio-head-bin"
