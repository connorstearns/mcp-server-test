from flask import Flask, request, jsonify, Response, stream_with_context, g
from googleapiclient.discovery import build
import logging
import os
import re
import time
import json

app = Flask(__name__)

# -------------------- Constants --------------------
SERVER_NAME = "gtm-audit-v5"
SERVER_VERSION = "0.3.2"  # stable rollback
MCP_PROTOCOL_VERSION_FALLBACK = "2024-11-05"

# GA4 tag template types
GA4_EVENT_TYPE = "gaawe"
GA4_CONFIG_TYPE = "gaawc"

# Allow write operations only when this is set truthy
ALLOW_WRITES = os.getenv("ALLOW_GTM_WRITES", "0") not in ("0", "false", "False", "")

# Optional: serve versioned paths like /v1/.well-known/mcp.json
VERSION_PREFIXES = ["/v1"]

# -------------------- Helpers --------------------
def _require_writes():
    if not ALLOW_WRITES:
        raise RuntimeError("Write operations are disabled. Set ALLOW_GTM_WRITES=1 to enable.")

def get_tagmanager_service():
    return build("tagmanager", "v2", cache_discovery=False)

def first_workspace_path(svc, account_id, container_id, workspace_id=None):
    parent = f"accounts/{account_id}/containers/{container_id}"
    if workspace_id:
        return f"{parent}/workspaces/{workspace_id}"
    resp = svc.accounts().containers().workspaces().list(parent=parent).execute()
    w = resp.get("workspace", []) or []
    if not w:
        raise RuntimeError("No workspaces found in container.")
    return w[0]["path"]

def resolve_workspace_path(svc, account_id, container_id, workspace_id=None):
    parent = f"accounts/{account_id}/containers/{container_id}"
    resp = svc.accounts().containers().workspaces().list(parent=parent).execute()
    workspaces = resp.get("workspace", []) or []
    ids = [w.get("workspaceId") for w in workspaces]
    if not ids:
        raise RuntimeError("No workspaces found in container.")
    if not workspace_id:
        return f"{parent}/workspaces/{ids[0]}", ids
    if str(workspace_id) in map(str, ids):
        return f"{parent}/workspaces/{workspace_id}", ids
    raise ValueError(f"Workspace '{workspace_id}' not found. Valid IDs: {', '.join(map(str, ids))}")

def _ws_path(account_id, container_id, workspace_id):
    return f"accounts/{account_id}/containers/{container_id}/workspaces/{workspace_id}"

def _bool_str(b):
    return "true" if bool(b) else "false"

def _sanitize_name(s: str) -> str:
    # GTM rejects ":" and we avoid newlines too
    s = re.sub(r"[:\r\n]", " - ", s or "")
    s = re.sub(r"\s+", " ", s).strip()
    return s or "Untitled"

# ---- Parameter builders (lowercase types that previously worked) ----
def P_template(key, value):
    return {"type": "template", "key": key, "value": str(value)}

def P_bool(key, value):
    return {"type": "boolean", "key": key, "value": _bool_str(value)}

def P_int(key, value):
    return {"type": "integer", "key": key, "value": str(int(value))}

def P_list_str(key, items):
    return {"type": "list", "key": key, "list": [{"type": "template", "value": str(x)} for x in items]}

def P_trigger_refs(key, trigger_ids):
    return {"type": "list", "key": key, "list": [{"type": "triggerReference", "value": str(t)} for t in trigger_ids]}

def _event_parameters_list(params_dict):
    if not params_dict:
        return None
    lst = []
    for k, v in params_dict.items():
        lst.append({
            "type": "map",
            "map": [
                {"type": "template", "key": "name", "value": str(k)},
                {"type": "template", "key": "value", "value": str(v)},
            ],
        })
    return {"type": "list", "key": "eventParameters", "list": lst}

# ---- MCP helpers (text-only results so Claude renders reliably) ----
def _mcp_text(txt: str):
    return {"content": [{"type": "text", "text": txt}]}

def _ok_text(title: str, data_obj=None):
    pretty = ""
    if data_obj is not None:
        pretty = "\n" + json.dumps(data_obj, indent=2, ensure_ascii=False)
    return _mcp_text(f"{title}{pretty}")

def _err_text(msg: str, data_obj=None):
    detail = ""
    if data_obj is not None:
        detail = "\n" + json.dumps(data_obj, indent=2, ensure_ascii=False)
    return {"isError": True, "content": [{"type": "text", "text": f"{msg}{detail}"}]}

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
def _cors_and_log(resp):
    # CORS & headers needed by Claude Web
    allow_headers = request.headers.get(
        "Access-Control-Request-Headers",
        "Content-Type, Authorization, MCP-Protocol-Version, Mcp-Protocol-Version, Mcp-Session-Id",
    )
    origin = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = allow_headers
    resp.headers["Access-Control-Expose-Headers"] = "Mcp-Session-Id, MCP-Protocol-Version"

    # Ensure MCP protocol header is always present
    proto = request.headers.get("Mcp-Protocol-Version") or getattr(g, "mcp_protocol", None) or MCP_PROTOCOL_VERSION_FALLBACK
    resp.headers["MCP-Protocol-Version"] = proto

    app.logger.info("RESP %s %s -> %s", request.method, request.path, resp.status)
    return resp

@app.route("/", methods=["OPTIONS"])
@app.route("/mcp/tools", methods=["OPTIONS"])
def _options_ok():
    return ("", 204)

# -------------------- Tool descriptors --------------------
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
            "name": "list_workspaces",
            "description": "List workspace IDs and names for a container.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "accountId":   {"type": "string"},
                    "containerId": {"type": "string"}
                },
                "required": ["accountId","containerId"]
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
            "description": "Create a GA4 Event tag. Provide either measurementId OR a GA4 Config tag reference (configTagId or configTagName).",
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
                    "tagName":       {"type": "string"}
                },
                "required": ["accountId", "containerId", "workspaceId", "eventName", "triggerIds"]
            },
        },
        {
            "name": "create_trigger",
            "description": "Create a GTM Trigger (Pageview, DOM Ready, Window Loaded, Custom Event, Click, Link Click, Form Submission, History Change, Timer, JS Error, Element Visibility, YouTube Video, Trigger Group).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "accountId":   {"type": "string"},
                    "containerId": {"type": "string"},
                    "workspaceId": {"type": "string"},
                    "type":        {"type": "string"},
                    "name":        {"type": "string"},

                    # Custom Event
                    "eventName": {"type": "string"},

                    # Link Click / Form Submission options
                    "waitForTags":        {"type": "boolean"},
                    "waitForTagsTimeout": {"type": "integer"},
                    "checkValidation":    {"type": "boolean"},

                    # Element Visibility options
                    "selectionMethod":    {"type": "string", "enum": ["CSS_SELECTOR", "ID"]},
                    "selector":           {"type": "string"},
                    "elementId":          {"type": "string"},
                    "minPercentVisible":  {"type": "integer"},
                    "observeDomChanges":  {"type": "boolean"},
                    "fireOnce":           {"type": "boolean"},

                    # Scroll Depth is not in this stable build (add later if needed)

                    # YouTube Video options
                    "captureStart":       {"type": "boolean"},
                    "captureComplete":    {"type": "boolean"},
                    "capturePause":       {"type": "boolean"},
                    "captureProgress":    {"type": "boolean"},
                    "progressThresholds": {"type": "array","items":{"type":"integer"}},

                    # Trigger Group
                    "groupTriggerIds":    {"type": "array","items":{"type":"string"}}
                },
                "required": ["accountId", "containerId", "workspaceId", "type"]
            },
        },
    ]
    return {"tools": tools}

# -------------------- Health --------------------
@app.route("/healthz", methods=["GET"], strict_slashes=False)
@app.route("/health", methods=["GET"], strict_slashes=False)
def healthz():
    return jsonify({"ok": True, "version": SERVER_VERSION}), 200

# -------------------- MCP discovery --------------------
@app.get("/.well-known/mcp.json")
def mcp_discovery():
    d = {
        "mcpVersion": "1.0",
        "name": SERVER_NAME,
        "version": SERVER_VERSION,
        "auth": {"type": "none"},
    }
    d.update(tools_descriptor())
    return jsonify(d)

# -------------------- MCP tools index --------------------
@app.route("/mcp/tools", methods=["GET"], strict_slashes=False)
def mcp_tools_index():
    app.logger.info("HIT /mcp/tools")
    return jsonify(tools_descriptor())

# -------------------- GET / (SSE keep-alive for web clients) --------------------
@app.route("/", methods=["GET"], strict_slashes=False)
def root_get():
    if "text/event-stream" in (request.headers.get("Accept") or ""):
        def _stream():
            yield ": connected\n\n"
            while True:
                time.sleep(25)
                yield ": ping\n\n"
        headers = {"Cache-Control": "no-store", "Connection": "keep-alive"}
        return Response(stream_with_context(_stream()), mimetype="text/event-stream", headers=headers)
    return jsonify({"ok": True, "message": "MCP server. Use POST / for JSON-RPC; see /.well-known/mcp.json and /mcp/*"}), 200

# -------------------- MCP invoke (REST convenience) --------------------
@app.post("/mcp/invoke")
def mcp_invoke():
    try:
        body = request.get_json(force=True) or {}
        action = body.get("action")
        params = body.get("params", {})

        if action == "audit_container":
            account_id = params.get("accountId"); container_id = params.get("containerId"); workspace_id = params.get("workspaceId")
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

        if action in ("create_ga4_config_tag", "create_ga4_event_tag", "create_trigger", "list_workspaces"):
            payload = {"jsonrpc": "2.0","id": 1,"method": "tools/call","params": {"name": action, "arguments": params}}
            with app.test_request_context(json=payload):
                return root_post()

        return jsonify({"ok": False, "error": f"Unsupported action '{action}'"}), 400
    except Exception as e:
        app.logger.exception("Error in /mcp/invoke")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------- Root JSON-RPC (single POST endpoint) --------------------
@app.route("/", methods=["POST"], strict_slashes=False)
def root_post():
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
            err = {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
            if data is not None:
                err["error"]["data"] = data
            return jsonify(err), http

        if method == "initialize":
            client_proto = params.get("protocolVersion") or MCP_PROTOCOL_VERSION_FALLBACK
            g.mcp_protocol = client_proto  # for after_request header
            result = {"protocolVersion": client_proto,"serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},"capabilities": {"tools": {}}}
            return rpc_result(result)

        if method in ("initialized", "notifications/initialized"):
            return rpc_result({"ok": True})

        if method in ("tools/list", "list_tools", "tools.index"):
            td = tools_descriptor()
            return rpc_result({"tools": td["tools"]})

        if method in ("tools/call", "call_tool"):
            name = params.get("name") or params.get("tool")
            args = params.get("arguments") or params.get("args") or {}

            try:
                # -------- list_workspaces --------
                if name == "list_workspaces":
                    svc = get_tagmanager_service()
                    a = args["accountId"]; c = args["containerId"]
                    parent = f"accounts/{a}/containers/{c}"
                    resp = svc.accounts().containers().workspaces().list(parent=parent).execute()
                    ws = [{"id": w.get("workspaceId"), "name": w.get("name",""), "description": w.get("description","")}
                          for w in (resp.get("workspace", []) or [])]
                    return rpc_result(_ok_text("Workspaces", {"workspaces": ws}))

                # -------- GA4 Config --------
                if name == "create_ga4_config_tag":
                    _require_writes()
                    svc = get_tagmanager_service()
                    account_id = args["accountId"]; container_id = args["containerId"]; workspace_id = args["workspaceId"]
                    measurement_id = args["measurementId"]
                    tag_name = _sanitize_name(args.get("tagName") or f"GA4 Config - {measurement_id}")
                    send_page_view = bool(args.get("sendPageView", True))

                    parent = _ws_path(account_id, container_id, workspace_id)
                    body = {
                        "name": tag_name,
                        "type": GA4_CONFIG_TYPE,
                        "parameter": [
                            P_bool("sendPageView", send_page_view),
                            P_template("measurementId", measurement_id),
                        ],
                    }
                    res = svc.accounts().containers().workspaces().tags().create(parent=parent, body=body).execute()
                    return rpc_result(_ok_text("GA4 Config tag created", res))

                # -------- GA4 Event --------
                if name == "create_ga4_event_tag":
                    _require_writes()
                    svc = get_tagmanager_service()
                    account_id = args["accountId"]; container_id = args["containerId"]; workspace_id = args["workspaceId"]
                    event_name = args["eventName"]
                    trigger_ids = [str(t) for t in (args.get("triggerIds") or [])]
                    if not trigger_ids:
                        return rpc_result(_err_text("create_ga4_event_tag: 'triggerIds' is required and must be a non-empty array"))

                    tag_name = _sanitize_name(args.get("tagName") or f"GA4 Event - {event_name}")
                    measurement_id = args.get("measurementId")
                    config_tag_id = args.get("configTagId")
                    config_tag_name = args.get("configTagName")
                    event_params = args.get("eventParameters") or {}

                    if not (measurement_id or config_tag_id or config_tag_name):
                        return rpc_result(_err_text("Provide either 'measurementId' or 'configTagId' or 'configTagName'"))

                    parent = _ws_path(account_id, container_id, workspace_id)
                    params_list = [P_template("eventName", event_name)]

                    if measurement_id:
                        params_list.append(P_template("measurementId", measurement_id))
                    elif config_tag_id:
                        params_list.append({"type": "tagReference", "key": "measurementId", "value": str(config_tag_id)})
                    else:
                        params_list.append({"type": "tagReference", "key": "measurementId", "value": config_tag_name})

                    ev_params = _event_parameters_list(event_params)
                    if ev_params:
                        params_list.append(ev_params)

                    body = {
                        "name": tag_name,
                        "type": GA4_EVENT_TYPE,
                        "firingTriggerId": trigger_ids,
                        "parameter": params_list,
                    }
                    res = svc.accounts().containers().workspaces().tags().create(parent=parent, body=body).execute()
                    return rpc_result(_ok_text("GA4 Event tag created", res))

                # -------- Create Trigger --------
                if name == "create_trigger":
                    _require_writes()
                    svc = get_tagmanager_service()
                    a = args["accountId"]; c = args["containerId"]; w = args.get("workspaceId")
                    ws_path, valid_ids = resolve_workspace_path(svc, a, c, w)

                    # Normalize & map type
                    t_in = (args.get("type") or "").strip().upper()
                    type_map = {
                        "PAGEVIEW": "pageview",
                        "DOM_READY": "domReady",
                        "WINDOW_LOADED": "windowLoaded",
                        "CUSTOM_EVENT": "customEvent",
                        "CLICK": "click",
                        "CLICK_ALL_ELEMENTS": "click",
                        "JUST_LINKS": "linkClick",
                        "LINK_CLICK": "linkClick",
                        "FORM_SUBMISSION": "formSubmission",
                        "HISTORY_CHANGE": "historyChange",
                        "TIMER": "timer",
                        "JAVASCRIPT_ERROR": "jsError",
                        "ELEMENT_VISIBILITY": "elementVisibility",
                        "YOUTUBE": "youTubeVideo",
                        "YOUTUBE_VIDEO": "youTubeVideo",
                        "TRIGGER_GROUP": "triggerGroup",
                    }
                    if t_in not in type_map:
                        return rpc_result(_err_text(f"Unsupported trigger type '{t_in}'"))
                    event_type = type_map[t_in]

                    trg_name = _sanitize_name(args.get("name") or f"{t_in.title()} Trigger")
                    body = {"name": trg_name, "type": event_type}

                    # Link Click / Form Submission options are top-level
                    if event_type in ("linkClick", "formSubmission"):
                        if "waitForTags" in args:        body["waitForTags"] = bool(args["waitForTags"])
                        if "checkValidation" in args:    body["checkValidation"] = bool(args["checkValidation"])
                        if "waitForTagsTimeout" in args: body["waitForTagsTimeout"] = int(args["waitForTagsTimeout"])

                    # Element Visibility -> parameter list
                    if event_type == "elementVisibility":
                        sel = (args.get("selectionMethod") or "").upper()
                        selector = args.get("selector"); element_id = args.get("elementId")
                        if sel not in ("CSS_SELECTOR", "ID"):
                            return rpc_result(_err_text("elementVisibility requires selectionMethod = CSS_SELECTOR or ID"))
                        params = [P_template("selectionMethod", sel)]
                        if sel == "CSS_SELECTOR":
                            if not selector: return rpc_result(_err_text("elementVisibility (CSS_SELECTOR) requires 'selector'"))
                            params.append(P_template("elementSelector", selector))
                        else:
                            if not element_id: return rpc_result(_err_text("elementVisibility (ID) requires 'elementId'"))
                            params.append(P_template("elementId", element_id))
                        if "minPercentVisible" in args: params.append(P_int("minPercentVisible", args["minPercentVisible"]))
                        if "observeDomChanges" in args: params.append(P_bool("observeDomChanges", args["observeDomChanges"]))
                        if "fireOnce" in args:          params.append(P_bool("fireOnce", args["fireOnce"]))
                        body["parameter"] = params

                    # YouTube Video -> parameter list
                    if event_type == "youTubeVideo":
                        params = []
                        params += [P_bool("captureStart",    bool(args.get("captureStart", True)))]
                        params += [P_bool("captureComplete", bool(args.get("captureComplete", True)))]
                        params += [P_bool("capturePause",    bool(args.get("capturePause", False)))]
                        params += [P_bool("captureProgress", bool(args.get("captureProgress", True)))]
                        thresholds = args.get("progressThresholds") or [10,25,50,75]
                        params.append(P_template("progressThresholds", ",".join(str(int(x)) for x in thresholds)))
                        body["parameter"] = params

                    # Timer -> parameter list
                    if event_type == "timer":
                        interval_ms = int(args.get("intervalMs") or args.get("interval") or 1000)
                        limit = int(args.get("limit") or 1)
                        body["parameter"] = [
                            P_template("eventName", "gtm.timer"),
                            P_int("interval", interval_ms),
                            P_int("limit", limit),
                        ]

                    # Trigger Group -> parameter list
                    if event_type == "triggerGroup":
                        ids = args.get("groupTriggerIds") or []
                        if not ids or len(ids) < 2:
                            return rpc_result(_err_text("triggerGroup requires 'groupTriggerIds' with 2+ trigger IDs"))
                        body["parameter"] = [P_trigger_refs("triggerIds", ids)]

                    res = svc.accounts().containers().workspaces().triggers().create(parent=ws_path, body=body).execute()
                    return rpc_result(_ok_text(f"Trigger created ({event_type})", res))

                # -------- Fallback audit via JSON-RPC path --------
                if name == "audit_container":
                    body = {"action": "audit_container", "params": args}
                    with app.test_request_context(json=body):
                        resp = mcp_invoke()
                    data = resp.get_json() if hasattr(resp, "get_json") else None
                    if data and isinstance(data, dict) and data.get("ok") is False:
                        return rpc_result(_err_text("Audit failed", data))
                    return rpc_result(_ok_text("GTM audit summary", data.get("result", {})))

                return rpc_result(_err_text(f"Unsupported tool '{name}'"))

            except ValueError as ve:
                return rpc_result(_err_text("Invalid workspaceId", {"message": str(ve)}))
            except Exception as e:
                app.logger.exception("Error in tools/call")
                return rpc_result(_err_text("Tool call failed", {"message": str(e)}))

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
