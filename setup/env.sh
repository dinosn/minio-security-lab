#!/usr/bin/env bash
# Common environment for the MinIO security lab.
# Source this: `. setup/env.sh`
#
# The lab is Docker-based; you need Docker + python3 (with the `cryptography`
# and `PyJWT` packages for the OIDC PoC only). No local minio/mc required.

export COMMIT=7aac2a2c5b7c882e68c1ce017d8256be2feea27f   # audited HEAD (~ RELEASE.2025-10-15 + 11)
export ROOT_USER=minioadmin
export ROOT_PASS=minioadmin123

# Endpoints
export S1=http://localhost:9000       # single node (default target)
export NODE_A=http://localhost:19000  # 2-node cluster / OIDC node
export NODE_B=http://localhost:19001  # 2-node cluster peer

# Which image the single-node lab uses. Override to a specific RELEASE tag if desired.
export MINIO_IMAGE=${MINIO_IMAGE:-minio/minio:latest}

# Persistent mc config so `mc alias` survives across invocations.
export MC_CONFIG_DIR=${MC_CONFIG_DIR:-$HOME/.mc-minio-lab}
mkdir -p "$MC_CONFIG_DIR"

# mc wrapper (containerised; no local mc install needed)
mc() { docker run --rm --network host -v "$MC_CONFIG_DIR":/root/.mc minio/mc "$@"; }
export -f mc 2>/dev/null || true

# Run an arbitrary shell script inside one mc container (for multi-command setup)
mcsh() { docker run --rm --network host -v "$MC_CONFIG_DIR":/root/.mc --entrypoint /bin/sh minio/mc -c "$1"; }
export -f mcsh 2>/dev/null || true

echo "[env] COMMIT=$COMMIT  S1=$S1  A=$NODE_A  B=$NODE_B  root=$ROOT_USER/$ROOT_PASS"
