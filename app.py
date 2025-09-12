from flask import Flask, request, jsonify, Response
from googleapiclient.discovery import build
import logging
import time
import os

app = Flask(__name__)

# -------------------- Constants --------------------
SERVER_NAME = "gtm-audit-v5"
SERVER_VERSION = "0.2.6"
MCP_PROTOCOL_VERSION = "2025-06-18"  # fallback only; we now echo the client's version

GA4_EVENT_TYPE = "gaawe"
GA4_CONFIG_TYPE = "gaawc"

# Optional static Bearer auth for Cloud Run (set AUTH_TOKEN to enable)
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "").strip()

# Allow write operations only when this is set truthy
ALLOW_WRITES = os.getenv("ALLOW_GTM_WRITES", "0") not in ("0", "false", "False", "")

# Optional: serve versioned paths like /v1/.well-known/mcp.json
VERSION_PREFIXES = ["/v1"]

# -------------------- Helpers --------------------
def _require_writes():
    if not ALLOW_WRITES:
        raise RuntimeError("Write operations are disabled. Set ALLOW_GTM_WRITES=1 to enable.")

def _require_auth():
    """If AUTH_TOKEN is set, require Authorization: Bearer <token>."""
    if not AUTH_TOKEN:
        return None
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return ("", 401)
    token = auth.split(" ", 1)[1]
    if token != AUTH_TOKEN:
        return ("", 403)
    return None

def get_tagmanager_service():
    # Uses Application Default Credentials (ADC) in Cloud Run
    return build("tagmanager", "v2")

def first_workspace_path(svc, account_id, container_id, workspace_id=None):
    parent = f"accounts/{account_id}/containers/{container_id}"
    if workspace_id:
        return f"{parent}/workspaces/{workspace_id}"
    resp = svc.accounts().containers().workspaces().list(parent=parent).execute()
    w = resp.get("workspace", [])
    if not w:
        raise RuntimeError("No workspaces found in container.")
    return w[0]["path"]

def _ws_path(account_id, container_id, workspace_id):
    return f"accounts/{account_id}/containers/{container_id}/workspaces/{workspace_id}"

def _bool_str(b):
    return "true" if bool(b) else "false"

def _event_parameters_list(params_dict):
    """
    Convert {"k":"v", ...} -> GTM list-of-maps for GA4 eventParameters.
    """
    if not params_dict:
        return None
    lst = []
    for k, v in params_dict.items():
        lst.append({
            "type": "MAP",
            "map": [
                {"type": "TEMPLATE", "key": "name", "value": str(k)},
                {"type": "TEMPLATE", "key": "value", "value": str(v)},
            ],
        })
    return {"type": "LIST", "key": "eventParameters", "list": lst}

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
            app.logger.info("version rewrite: %s -> %s", p, newp)
            request.environ["PATH_INFO"] = newp
            return

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

@app.route("/", methods=["OPTIONS"])
@app.route("/mcp/tools", methods=["OPTIONS"])
def _options_ok():
    return ("", 204)

# -------------------- Tool descriptors (SIMPLE schemas) --------------------
def tools_descriptor():
    tools = [
        {
            "name": "audit_container",
            "description": "Audit a GTM container and summarize GA4 tags/triggers.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "accountId":  {"type": "string"},
                    "containerId":{"type": "string"},
                    "workspaceId":{"type": "string"},
                },
                "required": ["accountId", "containerId"]
            },
        },
        {
            "name": "create_ga4_config_tag",
            "description": "Create a GA4 Configuration tag in a GTM workspace.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "accountId":    {"type": "string"},
                    "containerId":  {"type": "string"},
                    "workspaceId":  {"type": "string"},
                    "measurementId":{"type": "string"},
                    "tagName":      {"type": "string"},
                    "sendPageView": {"type": "boolean"},
                },
                "required": ["accountId", "containerId", "workspaceId", "measurementId"]
            },
        },
        {
            "name": "create_ga4_event_tag",
            "description": "Create a GA4 Event tag with measurement ID or config tag reference.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "accountId":     {"type": "string"},
                    "containerId":   {"type": "string"},
                    "workspaceId":   {"type": "string"},
                    "eventName":     {"type": "string"},
                    "triggerIds":    {"type": "array","items": {"type": "string"}},
                    "measurementId": {"type": "string"},
                    "configTagId":   {"type": "string"},
                    "configTagName": {"type": "string"},
                    "eventParameters": {"type": "object"},
                },
                "required": ["accountId", "containerId", "workspaceId", "eventName", "triggerIds"]
            },
        },
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

# -------------------- MCP tools index --------------------
@app.route("/mcp/tools", methods=["GET"], strict_slashes=False)
def mcp_tools_index():
    if (err := _require_auth()) is not None:
        return err
    app.logger.info("HIT /mcp/tools")
    return jsonify(tools_descriptor())

# -------------------- MCP invoke (generic) --------------------
@app.post("/mcp/invoke")
def mcp_invoke():
    try:
        if (err := _require_auth()) is not None:
            return err

        body = request.get_json(force=True) or {}
        action = body.get("action")
        params = body.get("params", {})

        if action == "audit_container":
            account_id = params.get("accountId")
            container_id = params.get("containerId")
            workspace_id = params.get("workspaceId")
            if not account_id or not container_id:
                return jsonify({"ok": False, "error": "Missing accountId or containerId"}), 400

            svc = get_tagmanager_service()
            ws_path = first_workspace_path(svc, account_id, container_id, workspace_id)

            tags = svc.accounts().containers().workspaces().tags().list(parent=ws_path).execute().get("tag", [])
            triggers = svc.accounts().containers().workspaces().triggers().list(parent=ws_path).execute().get("trigger", [])
            variables = svc.accounts().containers().workspaces().variables().list(parent=ws_path).execute().get("variable", [])

            ga4_config = [t for t in tags if t.get("type") == GA4_CONFIG_TYPE]
            ga4_events = [t for t in tags if t.get("type") == GA4_EVENT_TYPE]

            def event_name(tag):
                for p in tag.get("parameter", []):
                    if p.get("key") == "eventName":
                        return p.get("value", "unknown")
                return "unknown"

            summary = {
                "container": {"accountId": account_id, "containerId": container_id, "workspacePath": ws_path},
                "counts": {
                    "tags": len(tags),
                    "triggers": len(triggers),
                    "variables": len(variables),
                    "ga4_config_tags": len(ga4_config),
                    "ga4_event_tags": len(ga4_events),
                },
                "ga4": {
                    "has_config": len(ga4_config) > 0,
                    "events": [{"name": event_name(t), "tagId": t.get("tagId")} for t in ga4_events],
                },
                "triggers": [{"name": tr.get("name"), "type": tr.get("type"), "triggerId": tr.get("triggerId")} for tr in triggers],
                "warnings": [] if ga4_config else ["No GA4 Configuration tag found — GA4 events may not initialize properly."],
            }

            return jsonify({"ok": True, "result": summary})

        # Allow direct invoke of write tools by bridging to JSON-RPC tools/call
        if action in ("create_ga4_config_tag", "create_ga4_event_tag"):
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": action, "arguments": params},
            }
            with app.test_request_context(json=payload):
                return root_post()

        return jsonify({"ok": False, "error": f"Unsupported action '{action}'"}), 400
    except Exception as e:
        app.logger.exception("Error in /mcp/invoke")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------- Root JSON-RPC (single POST endpoint) --------------------
@app.route("/", methods=["GET"], strict_slashes=False)
def root_get():
    # Simple info (we keep GET non-redirecting for health/debug)
    if (err := _require_auth()) is not None:
        return err
    return jsonify({"ok": True, "message": "MCP server. Use POST / for JSON-RPC; see /.well-known/mcp.json and /mcp/*"}), 200

@app.route("/", methods=["POST"], strict_slashes=False)
def root_post():
    if (err := _require_auth()) is not None:
        return err

    payload = request.get_json(force=True) or {}
    app.logger.info("ROOT POST payload=%s", payload)

    if payload.get("jsonrpc") == "2.0":
        rpc_id = payload.get("id", None)
        method = (payload.get("method") or "").lower()
        params = payload.get("params") or {}
        app.logger.info("JSON-RPC method=%s id=%s", method, rpc_id)

        def rpc_result(result_obj, http=200):
            return jsonify({"jsonrpc": "2.0", "id": rpc_id, "result": result_obj}), http

        def rpc_error(code, message, data=None, http=200):
            # JSON-RPC best practice: 200 with error object (except auth failures)
            err = {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
            if data is not None:
                err["error"]["data"] = data
            return jsonify(err), http

        # 1) initialize — echo client's protocolVersion and advertise tools as {}
        if method == "initialize":
            td = tools_descriptor()
            client_proto = params.get("protocolVersion") or MCP_PROTOCOL_VERSION
            result = {
                "protocolVersion": client_proto,  # echo back what client sent
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "authentication": {"type": "oauth-bearer" if AUTH_TOKEN else "none"},
                "capabilities": {
                    "tools": {},       # golden shape
                    "resources": {},
                    "prompts": {},
                },
                "tools": td["tools"],  # harmless; many clients ignore
            }
            app.logger.info("initialize -> returning %d tools", len(td["tools"]))
            return rpc_result(result)

        # 2) notifications/initialized (no payload)
        if method in ("initialized", "notifications/initialized"):
            return ("", 204)

        # 3) tools/list — MUST return {"tools": [...]}
        if method in ("tools/list", "list_tools", "tools.index"):
            td = tools_descriptor()
            return rpc_result({"tools": td["tools"]})

        # 4) tools/call
        if method in ("tools/call", "call_tool"):
            name = params.get("name") or params.get("tool")
            args = params.get("arguments") or params.get("args") or {}

            # READ tool
            if name == "audit_container":
                body = {"action": "audit_container", "params": args}
                with app.test_request_context(json=body):
                    resp = mcp_invoke()
                data = resp.get_json() if hasattr(resp, "get_json") else None
                if data and isinstance(data, dict) and data.get("ok") is False:
                    return rpc_error(-32000, "Tool call failed", data)
                return rpc_result(data)

            # WRITE tools
            try:
                if name == "create_ga4_config_tag":
                    _require_writes()
                    svc = get_tagmanager_service()
                    account_id = args["accountId"]
                    container_id = args["containerId"]
                    workspace_id = args["workspaceId"]
                    measurement_id = args["measurementId"]
                    tag_name = args.get("tagName") or f"GA4 Config ({measurement_id})"
                    send_page_view = args.get("sendPageView", True)

                    parent = _ws_path(account_id, container_id, workspace_id)
                    body = {
                        "name": tag_name,
                        "type": GA4_CONFIG_TYPE,
                        "parameter": [
                            {"type": "BOOLEAN", "key": "sendPageView", "value": _bool_str(send_page_view)},
                            {"type": "TEMPLATE", "key": "measurementId", "value": measurement_id},
                        ],
                    }
                    res = svc.accounts().containers().workspaces().tags().create(parent=parent, body=body).execute()
                    return rpc_result({"ok": True, "result": res})

                if name == "create_ga4_event_tag":
                    _require_writes()
                    svc = get_tagmanager_service()
                    account_id = args["accountId"]
                    container_id = args["containerId"]
                    workspace_id = args["workspaceId"]
                    event_name = args["eventName"]
                    trigger_ids = [str(t) for t in (args.get("triggerIds") or [])]
                    measurement_id = args.get("measurementId")
                    config_tag_id = args.get("configTagId")
                    config_tag_name = args.get("configTagName")
                    event_params = args.get("eventParameters") or {}

                    if not trigger_ids:
                        return rpc_error(-32602, "triggerIds is required and must be a non-empty array")

                    parent = _ws_path(account_id, container_id, workspace_id)
                    params_list = [{"type": "TEMPLATE", "key": "eventName", "value": event_name}]

                    # Bind to GA4 config by one of the three options
                    if measurement_id:
                        params_list.append({"type": "TEMPLATE", "key": "measurementId", "value": measurement_id})
                    elif config_tag_id:
                        params_list.append({"type": "TAG_REFERENCE", "key": "measurementId", "value": str(config_tag_id)})
                    elif config_tag_name:
                        params_list.append({"type": "TAG_REFERENCE", "key": "measurementId", "value": config_tag_name})
                    else:
                        return rpc_error(-32602, "Provide either 'measurementId' or 'configTagId' or 'configTagName'")

                    ev_params = _event_parameters_list(event_params)
                    if ev_params:
                        params_list.append(ev_params)

                    body = {
                        "name": f"GA4 Event: {event_name}",
                        "type": GA4_EVENT_TYPE,
                        "firingTriggerId": trigger_ids,
                        "parameter": params_list,
                    }
                    res = svc.accounts().containers().workspaces().tags().create(parent=parent, body=body).execute()
                    return rpc_result({"ok": True, "result": res})

                return rpc_error(-32601, f"Unsupported tool '{name}'")

            except Exception as e:
                app.logger.exception("Error in tools/call")
                return rpc_error(-32000, "Tool call failed", {"message": str(e)})

        # 5) ping/health
        if method in ("ping", "health"):
            return rpc_result({"ok": True})

        return rpc_error(-32601, f"Method '{method}' not found")

    # ---- Simple "type" path (compat) ----
    t = (payload.get("type") or "").lower()
    if t in ("tools/list", "list_tools", "tools-index"):
        return jsonify(tools_descriptor())
    if t in ("tools/call", "call_tool"):
        name = payload.get("name") or payload.get("tool")
        args = payload.get("arguments") or payload.get("params") or {}
        with app.test_request_context(
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
        ):
            return root_post()
    if t in ("ping", "health", "heartbeat"):
        return jsonify({"ok": True}), 200

    # Default echo
    return jsonify({"ok": True, "echo": payload}), 200

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
