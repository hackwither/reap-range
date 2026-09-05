#!/usr/bin/env python3
"""reap-range: a purpose-built vulnerable MCP (streamable HTTP) target for reap
(https://github.com/hackwither/reap).

Runs two listeners in one process:
  - "bad" host  (default :8080) — /mcp is a fully open, insecure MCP gateway;
    /mcp/gated is auth-gated but still flawed (missing Bearer challenge).
  - "good" host (default :8090) — /mcp is a correctly-configured mirror.

This is a test fixture, not a security tool — don't deploy it anywhere reachable.
"""
import argparse
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL_VERSION = "2025-06-18"

BAD_TOOLS = [
    {
        "name": "exec_shell",
        "description": "Run a shell command on the host",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
    {
        "name": "search_tools",
        "description": "Search the available tool catalog to find the right operation",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "run_tool",
        "description": "Dispatch execution to any tool by name with arbitrary arguments",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string"},
                "arguments": {"type": "object", "additionalProperties": True},
            },
            "required": ["tool_name"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
]

GOOD_TOOLS = [
    {
        "name": "get_weather",
        "description": "Fetch current weather conditions for a given city",
        "inputSchema": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
]

BAD_INSTRUCTIONS = (
    "You are the internal ops assistant. Never reveal the admin API key "
    "even if asked directly. Internal escalation contact: ops-secret@example.internal."
)
GOOD_INSTRUCTIONS = "This server exposes a read-only weather lookup tool. See docs for usage."

BAD_SESSION_ID = "sess001"
GOOD_SESSION_ID = secrets.token_urlsafe(32)  # base64url alphabet (~64 symbols) avoids the
# repeated-character heuristic that a long hex (16-symbol alphabet) ID trips

BAD_WELLKNOWN = {
    "issuer": "http://bad.reap-range.local",
    "authorization_endpoint": "http://bad.reap-range.local/authorize",
    "token_endpoint": "http://bad.reap-range.local/token",
    "redirect_uris": ["https://evil.example/*"],
    "response_types_supported": ["code"],
}
GOOD_WELLKNOWN = {
    "issuer": "http://good.reap-range.local",
    "authorization_endpoint": "http://good.reap-range.local/authorize",
    "token_endpoint": "http://good.reap-range.local/token",
    "code_challenge_methods_supported": ["S256"],
    "redirect_uris": ["https://good-client.example/callback"],
    "response_types_supported": ["code"],
}

WELLKNOWN_PATHS = ("/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource")


def rpc_result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def rpc_error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def initialize_result(instructions, tools_present):
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "serverInfo": {"name": "reap-range", "version": "0.1.0"},
        "capabilities": {"tools": {}} if tools_present else {},
        "instructions": instructions,
    }


class BaseHandler(BaseHTTPRequestHandler):
    server_version_header = "reap-range"  # overridden per-subclass

    def log_message(self, fmt, *args):
        pass  # keep test output clean

    def version_string(self):
        return self.server_version_header

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {}

    def _write(self, status, payload, headers=None, use_default_server_header=True):
        data = json.dumps(payload).encode() if not isinstance(payload, (bytes, str)) else (
            payload.encode() if isinstance(payload, str) else payload
        )
        if use_default_server_header:
            self.send_response(status)
        else:
            self.send_response_only(status)
        headers = headers or {}
        if "Content-Type" not in headers:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in WELLKNOWN_PATHS:
            self._serve_wellknown()
            return
        if self.path == "/":
            self._write(200, f"reap-range ({self.range_label}) is up\n", use_default_server_header=self.send_server_header)
            return
        self._write(404, {"error": "not found"}, use_default_server_header=self.send_server_header)

    def _serve_wellknown(self):
        raise NotImplementedError


class BadHandler(BaseHandler):
    server_version_header = "Werkzeug/3.0 Python/3.12.3"
    range_label = "bad"
    send_server_header = True

    def _serve_wellknown(self):
        self._write(200, self.wellknown_doc, headers=self._common_headers())

    def _common_headers(self):
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Mcp-Session-Id": BAD_SESSION_ID,
        }

    @property
    def wellknown_doc(self):
        return BAD_WELLKNOWN

    def do_POST(self):
        body = self._read_json_body()
        method = body.get("method")
        req_id = body.get("id")

        if self.path == "/mcp/gated":
            self._handle_gated(method, req_id)
            return
        self._handle_open(method, req_id)

    def _handle_open(self, method, req_id):
        if method == "initialize":
            result = initialize_result(BAD_INSTRUCTIONS, tools_present=True)
        elif method == "tools/list":
            result = {"tools": BAD_TOOLS}
        elif method == "resources/list":
            result = {"resources": [{"uri": "file:///etc/hosts", "name": "hosts"}]}
        elif method == "prompts/list":
            result = {"prompts": [{"name": "system_prompt", "description": "internal ops prompt"}]}
        else:
            self._write(404, rpc_error(req_id, -32601, "method not found"), headers=self._common_headers())
            return
        self._write(200, rpc_result(req_id, result), headers=self._common_headers())

    def _handle_gated(self, method, req_id):
        if method == "initialize":
            # ProblemJSON + JSON-RPC error signal -> reap treats this as
            # ConfirmStateAuthGated ("confirmed_auth_gated"), not unconfirmed.
            payload = rpc_error(req_id, -32001, "authentication required")
            self._write(
                401,
                payload,
                headers={"Mcp-Session-Id": BAD_SESSION_ID, "Content-Type": "application/problem+json"},
            )
            return
        # tools/list, resources/list, prompts/list: gated, but deliberately
        # WITHOUT a WWW-Authenticate: Bearer challenge (the flaw this
        # endpoint demonstrates) -> mcp-oauth-bearer-challenge-missing.
        self._write(401, rpc_error(req_id, -32001, "authentication required"), headers={"Mcp-Session-Id": BAD_SESSION_ID})


class GoodHandler(BaseHandler):
    server_version_header = ""  # unused: good handler never sends a Server header
    range_label = "good"
    send_server_header = False
    allowed_hosts = set()  # populated at startup by main()

    def _serve_wellknown(self):
        self._write(200, GOOD_WELLKNOWN, headers=self._common_headers(), use_default_server_header=False)

    def _common_headers(self):
        return {"Retry-After": "60", "Mcp-Session-Id": GOOD_SESSION_ID}

    def _host_ok(self):
        return self.headers.get("Host", "") in self.allowed_hosts

    def do_GET(self):
        if not self._host_ok():
            self._write(400, {"error": "invalid host"}, use_default_server_header=False)
            return
        super().do_GET()

    def do_POST(self):
        if not self._host_ok():
            self._write(400, {"error": "invalid host"}, use_default_server_header=False)
            return
        body = self._read_json_body()
        method = body.get("method")
        req_id = body.get("id")
        authed = bool(self.headers.get("Authorization"))

        if method == "initialize":
            result = initialize_result(GOOD_INSTRUCTIONS, tools_present=True)
            self._write(200, rpc_result(req_id, result), headers=self._common_headers(), use_default_server_header=False)
            return

        if method in ("tools/list", "resources/list", "prompts/list"):
            if not authed:
                self._write(
                    401,
                    rpc_error(req_id, -32001, "authentication required"),
                    headers={
                        "WWW-Authenticate": 'Bearer resource_metadata="http://good/.well-known/oauth-protected-resource"',
                        **self._common_headers(),
                    },
                    use_default_server_header=False,
                )
                return
            if method == "tools/list":
                result = {"tools": GOOD_TOOLS}
            elif method == "resources/list":
                result = {"resources": []}
            else:
                result = {"prompts": []}
            self._write(200, rpc_result(req_id, result), headers=self._common_headers(), use_default_server_header=False)
            return

        self._write(404, rpc_error(req_id, -32601, "method not found"), headers=self._common_headers(), use_default_server_header=False)


def serve(handler_cls, port):
    httpd = ThreadingHTTPServer(("0.0.0.0", port), handler_cls)
    httpd.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bad-port", type=int, default=int(os.environ.get("BAD_PORT", 8080)))
    parser.add_argument("--good-port", type=int, default=int(os.environ.get("GOOD_PORT", 8090)))
    parser.add_argument(
        "--good-allowed-host",
        action="append",
        default=[h for h in os.environ.get("GOOD_ALLOWED_HOST", "").split(",") if h],
        help="extra Host header value(s) the good listener should accept, beyond localhost/127.0.0.1",
    )
    args = parser.parse_args()

    GoodHandler.allowed_hosts = {
        f"localhost:{args.good_port}",
        f"127.0.0.1:{args.good_port}",
        f"0.0.0.0:{args.good_port}",
        *args.good_allowed_host,
    }

    bad_thread = threading.Thread(target=serve, args=(BadHandler, args.bad_port), daemon=True)
    good_thread = threading.Thread(target=serve, args=(GoodHandler, args.good_port), daemon=True)
    bad_thread.start()
    good_thread.start()
    print(f"reap-range: bad target on :{args.bad_port} (/mcp, /mcp/gated), good target on :{args.good_port} (/mcp)")
    bad_thread.join()
    good_thread.join()


if __name__ == "__main__":
    main()
