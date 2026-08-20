#!/usr/bin/env python3
"""Minimal dual mock OIDC IdP + token minter for MinIO F-03 (cross-provider key confusion).
serve:  python3 mock_idp.py serve            # runs provider A on :8801, B on :8802
mint:   python3 mock_idp.py mint <a|b> <iss> <aud> <sub> [exp_seconds|none]  -> prints a signed JWT
Keys persist to /tmp/idp_<a|b>_{priv,pub}.pem so serve and mint agree.
"""
import sys, os, json, time, base64, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt as pyjwt

PROV = {
    "a": {"port": 8801, "kid": "keyA", "iss": "http://127.0.0.1:8801"},
    "b": {"port": 8802, "kid": "keyB", "iss": "http://127.0.0.1:8802"},
}

def keypaths(p): return f"/tmp/idp_{p}_priv.pem", f"/tmp/idp_{p}_pub.pem"

def ensure_keys(p):
    priv_f, pub_f = keypaths(p)
    if os.path.exists(priv_f):
        return
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    open(priv_f, "wb").write(k.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(pub_f, "wb").write(k.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))

def b64u(n):
    b = n.to_bytes((n.bit_length()+7)//8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def jwks(p):
    ensure_keys(p)
    _, pub_f = keypaths(p)
    pub = serialization.load_pem_public_key(open(pub_f,"rb").read())
    nums = pub.public_numbers()
    return {"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":PROV[p]["kid"],
                     "n":b64u(nums.n),"e":b64u(nums.e)}]}

def discovery(p):
    iss = PROV[p]["iss"]
    return {"issuer":iss,"jwks_uri":f"{iss}/jwks",
            "authorization_endpoint":f"{iss}/auth","token_endpoint":f"{iss}/token",
            "response_types_supported":["id_token","code"],
            "subject_types_supported":["public"],
            "id_token_signing_alg_values_supported":["RS256"],
            "scopes_supported":["openid"],"claims_supported":["sub","aud","iss","exp"]}

def make_handler(p):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if self.path.startswith("/.well-known/openid-configuration"):
                body = json.dumps(discovery(p)).encode()
            elif self.path.startswith("/jwks"):
                body = json.dumps(jwks(p)).encode()
            else:
                self.send_response(404); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body))); self.end_headers()
            self.wfile.write(body)
    return H

def serve():
    for p in ("a","b"): ensure_keys(p)
    servers=[]
    for p in ("a","b"):
        s=HTTPServer(("0.0.0.0",PROV[p]["port"]), make_handler(p))
        t=threading.Thread(target=s.serve_forever, daemon=True); t.start(); servers.append(s)
        print(f"provider {p} on :{PROV[p]['port']} iss={PROV[p]['iss']}")
    print("serving; ctrl-c to stop");
    while True: time.sleep(3600)

def mint():
    p, iss, aud, sub = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
    exp_arg = sys.argv[6] if len(sys.argv)>6 else "3600"
    ensure_keys(p)
    priv_f,_ = keypaths(p)
    priv = open(priv_f,"rb").read()
    claims = {"iss":iss, "aud":aud, "sub":sub, "iat":int(time.time()), "nbf":int(time.time())}
    if exp_arg != "none":
        claims["exp"] = int(time.time()) + int(exp_arg)
    # MinIO role_policy mode maps to policy via roleArn, not claim; include a groups/policy claim too
    claims["groups"] = ["ignored"]
    tok = pyjwt.encode(claims, priv, algorithm="RS256", headers={"kid":PROV[p]["kid"]})
    print(tok)

if __name__ == "__main__":
    if sys.argv[1]=="serve": serve()
    elif sys.argv[1]=="mint": mint()
