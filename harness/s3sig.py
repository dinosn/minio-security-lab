#!/usr/bin/env python3
"""Minimal stdlib AWS SigV4 (S3) signer for MinIO security testing.
Signs with an explicit signed-header set, then lets you attach EXTRA UNSIGNED
headers/queries — for testing "unsigned header injection" style bugs.
Usage: import s3sig; s3sig.send(ak, sk, method, path, ...)
"""
import hmac, hashlib, datetime, urllib.request, urllib.error, sys

def _sha256(b): return hashlib.sha256(b).hexdigest()
def _hmac(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()
def _uriencode(s, encode_slash=True):
    safe = "-_.~"
    out = []
    for ch in s:
        if ch.isalnum() or ch in safe: out.append(ch)
        elif ch == "/" and not encode_slash: out.append(ch)
        else:
            for b in ch.encode(): out.append("%%%02X" % b)
    return "".join(out)

def send(ak, sk, method, path, query=None, signed_headers=None, extra_headers=None,
         payload=b"", host="localhost:9000", scheme="http", region="us-east-1",
         service="s3", content_sha256=None, amzdate=None, timeout=15, sts_token=None):
    query = query or {}
    extra_headers = extra_headers or {}
    now = datetime.datetime.utcnow()
    amzdate = amzdate or now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = amzdate[:8]
    if content_sha256 is None:
        content_sha256 = _sha256(payload)
    # base signed headers
    hdrs = {"host": host, "x-amz-content-sha256": content_sha256, "x-amz-date": amzdate}
    if sts_token:
        hdrs["x-amz-security-token"] = sts_token
    if signed_headers:
        for k, v in signed_headers.items():
            hdrs[k.lower()] = v
    canon_uri = _uriencode(path, encode_slash=False)
    # canonical query
    qitems = sorted((_uriencode(str(k)), _uriencode(str(v))) for k, v in query.items())
    canon_qs = "&".join(f"{k}={v}" for k, v in qitems)
    signed_names = ";".join(sorted(hdrs.keys()))
    canon_hdrs = "".join(f"{k}:{hdrs[k].strip()}\n" for k in sorted(hdrs.keys()))
    canon_req = f"{method}\n{canon_uri}\n{canon_qs}\n{canon_hdrs}\n{signed_names}\n{content_sha256}"
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    sts = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{_sha256(canon_req.encode())}"
    kdate = _hmac(("AWS4" + sk).encode(), datestamp)
    kregion = hmac.new(kdate, region.encode(), hashlib.sha256).digest()
    kservice = hmac.new(kregion, service.encode(), hashlib.sha256).digest()
    ksign = hmac.new(kservice, b"aws4_request", hashlib.sha256).digest()
    sig = hmac.new(ksign, sts.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
            f"SignedHeaders={signed_names}, Signature={sig}")
    # build request: signed headers + Authorization + EXTRA UNSIGNED headers
    send_headers = {k: v for k, v in hdrs.items()}
    send_headers["Authorization"] = auth
    for k, v in extra_headers.items():
        send_headers[k] = v  # unsigned
    url = f"{scheme}://{host}{path}"
    if canon_qs:
        url += "?" + "&".join(f"{k}={v}" for k, v in qitems)
    req = urllib.request.Request(url, data=payload if method in ("PUT","POST","DELETE") else None,
                                 method=method, headers=send_headers)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return -1, {}, str(e).encode()

if __name__ == "__main__":
    # positive control: signed GET of an object
    ak, sk = sys.argv[1], sys.argv[2]
    method = sys.argv[3] if len(sys.argv) > 3 else "GET"
    path = sys.argv[4] if len(sys.argv) > 4 else "/tenant-a/secret.txt"
    st, h, b = send(ak, sk, method, path)
    print("STATUS", st)
    print("BODY", b[:400])
