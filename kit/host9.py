"""Codex local App Server observations. Sends no model turn."""
import json
import os
import selectors
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    binary, root, output = sys.argv[1:]
    root = Path(root)
    name = "commonwealth-operator-help"
    cwd = root / "workspace"
    marketplace = cwd / ".agents/plugins/marketplace.json"
    env = {"HOME": str(root / "home"), "CODEX_HOME": str(root / "home/.codex"),
           "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    command = [binary, "app-server"]
    errors = tempfile.TemporaryFile()
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=errors, bufsize=0)
    rows = []
    pending = bytearray()

    def request(method, params, identity):
        request = {"method": method, "params": params}
        if identity:
            request["id"] = identity
        process.stdin.write((json.dumps(request) + "\n").encode())
        if not identity:
            return {}
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            for _ in range(60):
                if b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending[:] = rest
                    response = json.loads(line)
                    if response.get("id") == identity:
                        rows.append({"method": method, "response": response})
                        return response
                else:
                    if not selector.select(3):
                        raise RuntimeError(f"host response timeout: {method}")
                    line = os.read(process.stdout.fileno(), 4096)
                    if not line:
                        raise RuntimeError("host exited")
                    pending.extend(line)
                    if len(pending) > 65536:
                        raise RuntimeError("host response exceeds evidence bound")
        raise RuntimeError(f"host response not found: {method}")

    result = {"verdict": "UNVERIFIED", "host": subprocess.check_output([binary, "--version"], env=env, text=True).strip()}
    try:
        request("initialize", {"clientInfo": {"name": "commonwealth-fixture", "version": "1"},
                               "capabilities": {"experimentalApi": True}}, 1)
        request("initialized", {}, None)
        request("plugin/list", {"cwds": [str(cwd)]}, 2)
        params = {"marketplacePath": str(marketplace), "pluginName": name}
        read = request("plugin/read", params, 3)
        install = request("plugin/install", params, 4)
        skills = request("skills/list", {"cwds": [str(cwd)], "forceReload": True}, 5)
        if ("result" in read and "result" in install and "result" in skills
                and "commonwealth-help" in json.dumps(skills["result"])):
            result["verdict"] = "PASS"
    except (RuntimeError, ValueError, OSError) as exc:
        result["incomplete"] = str(exc)
    finally:
        process.terminate()
        try:
            process.wait(3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    errors.seek(0)
    result["diagnostic"] = errors.read(2048).decode(errors="replace")
    errors.close()
    result["messages"] = rows
    Path(output).write_text(json.dumps(result))


if __name__ == "__main__":
    main()
