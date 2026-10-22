#!/usr/bin/env python3
"""Exercise the renamed native ACP profile without credentials or inference."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


class CatalogFixture(BaseHTTPRequestHandler):
    """Only catalog reads are allowed; an inference request fails the smoke."""

    unexpected_requests = []

    def do_GET(self):
        if self.path != "/coding-agent/v1/models":
            self.reject_request()
            return
        # Same minimal catalog contract as tests/e2e/tmux-helpers.ts.
        body = json.dumps({"data": [{"id": "openai/gpt-5",
                                    "type": "language", "tags": ["tool-use"]}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def reject_request(self):
        self.unexpected_requests.append((self.command, self.path))
        self.send_error(405, "Only the local model catalog may be read")

    do_POST = reject_request
    do_PUT = reject_request
    do_DELETE = reject_request
    do_PATCH = reject_request

    def log_message(self, *_args):
        pass

binary = str(Path(sys.argv[1]).resolve())
requests = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1, "clientCapabilities": {}}},
    {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"mcpServers": []}},
]
with ThreadingHTTPServer(("127.0.0.1", 0), CatalogFixture) as server:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="fortmend-fx-smoke-") as profile:
            # Whitelist process necessities rather than inheriting provider
            # credentials, proxies, personal profiles or project settings.
            env = {key: os.environ[key] for key in ("PATH", "TMPDIR", "SYSTEMROOT")
                   if key in os.environ}
            base = f"http://127.0.0.1:{server.server_port}"
            env.update({
                "HOME": profile, "XDG_CONFIG_HOME": profile,
                "XDG_CACHE_HOME": profile, "VERCEL_OIDC_TOKEN": "",
                "AI_GATEWAY_API_KEY": "fortmend-local-smoke-placeholder",
                "FX_GATEWAY_BASE_URL": base,
                "FX_GATEWAY_CHAT_URL": base + "/chat",
                "FX_E2E_GATEWAY_CHAT_URL": base + "/chat",
                "FX_E2E_GATEWAY_MODELS_URL": base + "/coding-agent/v1/models",
                "FX_MODEL": "openai/gpt-5", "FX_AUTO_UPGRADE": "0",
            })
            result = subprocess.run([binary, "acp", "--fortmend"],
                input="".join(json.dumps(request) + "\n" for request in requests),
                text=True, capture_output=True, timeout=20, env=env, cwd=profile)
            assert result.returncode == 0, result.stderr
            responses = {item["id"]: item for line in result.stdout.splitlines()
                         if (item := json.loads(line)) and "id" in item}
            assert "result" in responses.get(1, {}), result.stdout
            assert responses.get(2, {}).get("result", {}).get("sessionId"), result.stdout
            assert not result.stderr.strip(), result.stderr
            assert not CatalogFixture.unexpected_requests, CatalogFixture.unexpected_requests
    finally:
        server.shutdown()
        thread.join(timeout=5)
print("Fortmend ACP initialize + session/new passed (no inference).")
