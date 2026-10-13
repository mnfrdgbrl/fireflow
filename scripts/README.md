# Scripts

The four scripts that carried the Fireflow chain. Each is written to be read
and understood; secrets, the flow ID, and the node address are left as
placeholders (`<FLOW_ID>`, `<bot>`, `<target>`, …) — fill them from your own run.

> For educational and authorized testing only. See [../DISCLAIMER.md](../DISCLAIMER.md).

## Requirements

- Python 3.10+
- `requests` (for `fireflow_rce.py`), run from your attack box
- `websockets` (for `kexec_v4.py`), run **inside the MCP pod** — it is already
  present there; register the script as a tool via `mcp_client.py`

## Order of use

| # | Script | Where it runs | Purpose |
|---|--------|---------------|---------|
| 1 | `fireflow_rce.py` | attack box | Langflow unauth RCE; dump `env` to recover reused credentials |
| 2 | `jwt_matrix.py` | attack box / foothold | find which `alg:none` forge the MCP server accepts |
| 3 | `mcp_client.py` | attack box / foothold | forge the admin token, register a tool, call it |
| 4 | `kexec_v4.py` | inside the MCP pod | kubelet exec into the privileged pod → root |

## Notes on the tricky parts

**`fireflow_rce.py` — why the payload shape matters.** Langflow's loader scans
the submitted code for a class whose base name contains `Component` *before* it
runs anything, and the executor only runs *definition* statements. So the
command and the output-raising live inside a class body, and `Component` is a
local dummy class (no import needed). Output is read inline from the build
stream with `?event_delivery=direct` — no reverse shell, no filesystem.

**`mcp_client.py` — the forge.** The only token the server accepts is lowercase
`alg:none` with an **empty but present** signature (so the token still has three
dot-separated segments — note the trailing dot), carrying `role:admin`. Tool
`code` runs server-side and the server captures **stdout**, so tools `print()`.

**`kexec_v4.py` — the kubelet params.** The persistent `400: you must specify at
least 1 of stdin, stdout, stderr` is caused by the parameter names and values:
the kubelet reads `input` / `output` / `error` (not `stdin`/`stdout`/`stderr`)
and compares against the string `"1"` (not `"true"`). Use `output=1&error=1`,
subprotocol `v4.channel.k8s.io`, and read stdout off channel byte `1`.
