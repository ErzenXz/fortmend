#!/usr/bin/env python3
"""Exercise the renamed native ACP profile without credentials or inference."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
requests = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1, "clientCapabilities": {}}},
    {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"mcpServers": []}},
]
with tempfile.TemporaryDirectory(prefix="fortmend-fx-smoke-") as profile:
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("FX_", "OPENAI_", "ANTHROPIC_", "AI_GATEWAY_"))}
    env["HOME"] = profile
    result = subprocess.run([binary, "acp", "--fortmend"],
        input="".join(json.dumps(request) + "\n" for request in requests),
        text=True, capture_output=True, timeout=20, env=env)
    assert result.returncode == 0, result.stderr
    responses = {item["id"]: item for line in result.stdout.splitlines()
                 if (item := json.loads(line)) and "id" in item}
    assert "result" in responses.get(1, {}), result.stdout
    assert responses.get(2, {}).get("result", {}).get("sessionId"), result.stdout
    assert not result.stderr.strip(), result.stderr
print("Fortmend ACP initialize + session/new passed (no inference).")
