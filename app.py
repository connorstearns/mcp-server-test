from flask import Flask, request, jsonify, Response
import logging
import time
import os

app = Flask(__name__)

# -------------------- Constants --------------------
SERVER_NAME = "gtm-audit-v5"
SERVER_VERSION = "0.2.6"
MCP_PROTOCOL_VERSION = "2025-06-18"  # keep in case clients call initialize

# Dedicated SSE path expected by Anthropic connector
SSE_PATH = "/sse"

# Optional Bearer token; if set, all endpoints require Authorization: Bearer <token>
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "").strip()

# Optional versioned prefixes like /v1/sse
VERSION_PREFIXES = ["/v1"]

# -------------------- Auth --------------------
def _require_auth():
    if not AUTH_TOKEN:
        return  # auth disabled
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return ("", 401)
    token = auth.split(" ", 1)[1]
    if token != AUTH_TOKEN:
        return ("", 403)
    return None

# -------------------- Logging --------------------
logging.basicConfig(level=logging.INFO)

@app.before_request
def _log_req():
    app.logger.info("REQ %s %s headers=%s", request.method, request.path, dict(request.headers))

@app.after_request
def _log_resp(resp):
    # CORS (skip for SSE)
    if resp.mimetype != "text/event-stream":
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Mcp-Protocol-Version"
    app.logger.info("RESP %s %s -> %s", request.method, request.path, resp.status)
    return resp

# -------------------- Versioned URL rewrite (FIRST before_request) --------------------
@app.before_request
def _support_version_prefix():
    p = request.path
    for pref in VERSION_PREFIXES:
        if p == pref:
            app.logger.info("version rewrite: %s -> /", p)
            request.environ["PATH_INFO"] = "/"
            return
        if p.startswith(pref + "/"):
            newp = p[len(pref):] or "/"
            # carve out exact SSE alias too
            if newp == "/sse":
                request.environ["PATH_INFO"] = SSE_PATH
                return
            app.logger.info("version rewrite: %s -> %s", p, newp)
            request.environ["PATH_INFO"] = newp
            return

# -------------------- Options --------------------
@app.route("/", methods=["OPTIONS"])
@app.route("/mcp", methods=["OPTIONS"])
@app.route("/mcp/tools", methods=["OPTIONS"])
@app.route(SSE_PATH, methods=["OPTIONS"])
def _options_ok():
    return ("", 204)

# -------------------- Tools (MINIMAL) --------------------
def tools_descriptor():
    tools = [
        {
            "name": "test_tool",
            "description": "A simple test tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message": {"type": "string"}
                }
            }
        }
    ]
    return {"tools": tools}

# -------------------- Health --------------------
@app.route("/healthz", methods=["GET"], strict_slashes=False)
@app.route("/health", methods=["GET"], strict_slashes=False)
def healthz():
    if (err := _require_auth()) is not None:
        return err
    return jsonify({"ok": True, "version": SERVER_VERSION}), 200

# -------------------- MCP discovery --------------------
@app.get("/.well-known/mcp.json")
def mcp_discovery():
    if (err := _require_auth()) is not None:
        return err
    d = {
        "mcpVersion": "1.0",
        "name": SERVER_NAME,
        "version": SERVER_VERSION,
        "auth": {"type": "oauth-bearer" if AUTH_TOKEN else "none"},
    }
    d.update(tools_descriptor())
    return jsonify(d)

# -------------------- Tools index --------------------
@app.route("/mcp/tools", methods=["GET"], strict_slashes=False)
def mcp_tools_index():
    if (err := _require_auth()) is not None:
        return err
    app.logger.info("HIT /mcp/tools")
    return jsonify(tools_descriptor())

# -------------------- SSE endpoint (dedicated) --------------------
@app.get(SSE_PATH)
def sse_stream():
    if (err := _require_auth()) is not None:
        return err

    app.logger.info("Opening SSE stream on %s", SSE_PATH)
    interval = int(os.getenv("MCP_SSE_INTERVAL_SECONDS", "25"))
    max_secs = int(os.getenv("MCP_SSE_MAX_SECONDS", "0"))  # 0 = unlimited

    def stream():
        try:
            # A couple of greeting lines
            yield ": mcp-server ready\n\n"
            yield "event: ready\ndata: {}\n\n"
            start = time.time()
            while True:
                if max_secs > 0 and (time.time() - start) >= max_secs:
                    yield "event: bye\ndata: {}\n\n"
                    return
                time.sleep(interval)
                yield ": keepalive\n\n"
        except (GeneratorExit, BrokenPipeError):
            return

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )

# -------------------- JSON-RPC helpers --------------------
def _rpc_result(rpc_id, result_obj, http=200):
    return jsonify({"jsonrpc": "2.0", "id": rpc_id, "result": result_obj}), http

def _rpc_error(rpc_id, code, message, data=None, http=400):
    err = {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
    if data is not None:
        err["error"]["data"] = data
    return jsonify(err), http

# -------------------- Streamable HTTP (JSON-RPC) --------------------
@app.route("/", methods=["POST"], strict_slashes=False)
@app.route("/mcp", methods=["POST"], strict_slashes=False)
def root_post():
    if (err := _require_auth()) is not None:
        return err

    payload = request.get_json(force=True) or {}
    app.logger.info("ROOT POST payload=%s", payload)

    # JSON-RPC 2.0
    if payload.get("jsonrpc") == "2.0":
        rpc_id = payload.get("id", None)
        method = (payload.get("method") or "").lower()
        params = payload.get("params") or {}

        # 1) initialize — some clients still call this
        if method == "initialize":
            td = tools_descriptor()
            result = {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "authentication": {"type": "oauth-bearer" if AUTH_TOKEN else "none"},
                "capabilities": {"tools": {"enabled": True}, "resources": {}, "prompts": {}},
                "tools": td["tools"],
            }
            app.logger.info("initialize -> returning %d tools with capabilities", len(td["tools"]))
            return _rpc_result(rpc_id, result)

        # 2) notifications/initialized (no content body)
        if method in ("initialized", "notifications/initialized"):
            return ("", 204)

        # 3) tools/list — MUST return {"tools": [...]}
        if method in ("tools/list", "list_tools", "tools.index"):
            td = tools_descriptor()
            app.logger.info("tools/list -> returning %d tools", len(td["tools"]))
            return _rpc_result(rpc_id, {"tools": td["tools"]})

        # 4) tools/call
        if method in ("tools/call", "call_tool"):
            name = params.get("name") or params.get("tool")
            args = params.get("arguments") or params.get("args") or {}

            if name == "test_tool":
                msg = args.get("message", "")
                return _rpc_result(rpc_id, {"ok": True, "result": {"echo": msg, "length": len(msg)}})

            return _rpc_error(rpc_id, -32601, f"Unsupported tool '{name}'")

        # 5) ping/health
        if method in ("ping", "health"):
            return _rpc_result(rpc_id, {"ok": True})

        return _rpc_error(rpc_id, -32601, f"Method '{method}' not found")

    # ---- Simple "type" path (compat) ----
    t = (payload.get("type") or "").lower()
    if t in ("tools/list", "list_tools", "tools-index"):
        return jsonify(tools_descriptor())
    if t in ("tools/call", "call_tool"):
        name = payload.get("name") or payload.get("tool")
        args = payload.get("arguments") or payload.get("params") or {}
        # Simple bridge to JSON-RPC
        return root_post_bridge(name, args)
    if t in ("ping", "health", "heartbeat"):
        return jsonify({"ok": True}), 200

    # Default echo
    return jsonify({"ok": True, "echo": payload}), 200

def root_post_bridge(name, args):
    # Internal helper to emulate a JSON-RPC call for compat input
    fake_rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }
    with app.test_request_context(json=fake_rpc):
        return root_post()

# -------------------- Route inspector --------------------
@app.get("/__routes")
def routes():
    return jsonify(sorted([str(r) for r in app.url_map.iter_rules()]))

def _dump_routes_once():
    try:
        for r in app.url_map.iter_rules():
            app.logger.info("ROUTE %s methods=%s", r.rule, sorted(r.methods))
    except Exception as e:
        app.logger.warning("Could not dump routes: %s", e)

_dump_routes_once()

# -------------------- Entrypoint (dev) --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
