from flask import Flask, request, jsonify, Response, stream_with_context, g
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import logging, os, re, time, json

app = Flask(__name__)

# -------------------- Constants --------------------
SERVER_NAME = "gtm-audit-v6"
SERVER_VERSION = "0.4.0"
MCP_PROTOCOL_VERSION_FALLBACK = "2024-11-05"

# GA4 tag template types (GTM Web)
GA4_EVENT_TYPE  = "gaawe"
GA4_CONFIG_TYPE = "gaawc"

# Allow write operations only when this is truthy
ALLOW_WRITES = os.getenv("ALLOW_GTM_WRITES", "0") not in ("0", "false", "False", "")

# Optional: shared secret header gate (works for all POSTs)
MCP_SHARED_KEY = os.getenv("MCP_SHARED_KEY", "").strip()

# Optional: serve versioned paths like /v1/.well-known/mcp.json
VERSION_PREFIXES = ["/v1"]

# -------------------- Logging --------------------
logging.basicConfig(level=logging.INFO)
log = app.logger

# -------------------- Utilities --------------------
def _require_writes():
    if not ALLOW_WRITES:
        raise RuntimeError("Write operations are disabled. Set ALLOW_GTM_WRITES=1 to enable.")

def get_tagmanager_service():
    # You can inject a custom Http with timeouts/retries if desired
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

def _bool_str(b): return "true" if bool(b) else "false"

def _sanitize_name(s: str) -> str:
    s = re.sub(r"[:\r\n]", " - ", s or "")
    s = re.sub(r"\s+", " ", s).strip()
    return s or "Untitled"

# ---- Param builders (GTM expects these shapes) ----
def P_template(key, value): return {"type": "template", "key": key, "value": str(value)}
def P_bool(key, value):     return {"type": "boolean",  "key": key, "value": _bool_str(value)}
def P_int(key, value):      return {"type": "integer",  "key": key, "value": str(int(value))}
def P_list_str(key, items): return {"type": "list",     "key": key, "list": [{"type":"template","value":str(x)} for x in (items or [])]}
def P_trigger_refs(key, trigger_ids): return {"type": "list","key": key,"list":[{"type":"triggerReference","value": str(t)} for t in (trigger_ids or [])]}

def _event_parameters_list(params_dict):
    if not params_dict:
        return None
    lst = []
    for k, v in params_dict.items():
        lst.append({"type": "map","map":[{"type":"template","key":"name","value":str(k)},
                                         {"type":"template","key":"value","value":str(v)}]})
    return {"type":"list","key":"eventParameters","list": lst}

# ---- Filters (conditions) for triggers ----
# CSV/Excel uses friendly operators; map them to GTM condition "type" and args.
_OP_MAP = {
    "equals": "equals",
    "does_not_equal": "doesNotEqual",
    "contains": "contains",
    "does_not_contain": "doesNotContain",
    "starts_with": "startsWith",
    "ends_with": "endsWith",
    "matches_regex": "matchesRegex",
    "greater_than": "greater",
    "less_than": "less",
}

def _var_token(name: str) -> str:
    # If user passed {{Var}} keep as is; else wrap built-ins/user-defined by name.
    s = (name or "").strip()
    return s if s.startswith("{{") and s.endswith("}}") else f"{{{{{s}}}}}"

def _make_condition(var_name: str, op: str, val: str):
    op_key = _OP_MAP.get((op or "").strip())
    if not op_key:
        raise ValueError(f"Unsupported operator '{op}'")
    # GTM condition schema: {"type": <operator>, "parameter": [{"type":"template","key":"arg0","value":"{{Var}}"},{"type":"template","key":"arg1","value":"foo"}]}
    return {
        "type": op_key,
        "parameter": [
            {"type": "template", "key": "arg0", "value": _var_token(var_name)},
            {"type": "template", "key": "arg1", "value": str(val or "")},
        ],
    }

def _apply_filters_to_trigger_body(body: dict, filters: list, logic: str):
    """Attach filters to a trigger body. logic: 'ALL'(AND) or 'ANY'(OR).
       For OR, GTM expects a 'filter' list grouped in any/all; simplest way:
       - For ALL: use body['filter'] = [cond1, cond2, ...]
       - For ANY: use body['filter'] = [{"type":"or", "parameter":[cond1,cond2,...]}]  (fallback)
    """
    conditions = []
    for f in (filters or []):
        if not f: continue
        var, op, val = f.get("var"), f.get("op"), f.get("val")
        if not var or not op: continue
        conditions.append(_make_condition(var, op, val))
    if not conditions:
        return
    logic = (logic or "ALL").upper()
    if logic == "ALL":
        body["filter"] = conditions
    else:
        # Some clients flatten OR groups differently; this wrapper works in practice.
        body["filter"] = [{"type":"or","parameter": conditions}]

# ---- MCP helpers (text-only results so Claude/ChatGPT render reliably) ----
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

def _gtm_error_payload(where: str, err: Exception):
    if isinstance(err, HttpError):
        try:
            j = json.loads(err.content.decode("utf-8"))
        except Exception:
            j = {"error": {"message": str(err)}}
        e = j.get("error", {})
        return {"where": where, "status": getattr(err, "status_code", None), "reason": e.get("status"), "message": e.get("message")}
    return {"where": where, "message": str(err)}

# -------------------- Versioned URL rewrite --------------------
@app.before_request
def _support_version_prefix():
    p = request.path
    for pref in VERSION_PREFIXES:
        if p == pref:
            request.environ["PATH_INFO"] = "/"
            return
        if p.startswith(pref + "/"):
            request.environ["PATH_INFO"] = p[len(pref):] or "/"
            return

# -------------------- Logging & CORS --------------------
@app.before_request
def _log_req():
    if MCP_SHARED_KEY:
        auth = "present" if request.headers.get("X-MCP-Key") else "missing"
    else:
        auth = "disabled"
    log.info("REQ %s %s auth=%s", request.method, request.path, auth)

@app.after_request
def _cors_and_log(resp):
    allow_headers = request.headers.get(
        "Access-Control-Request-Headers",
        "Content-Type, Authorization, MCP-Protocol-Version, Mcp-Protocol-Version, Mcp-Session-Id, X-MCP-Key",
    )
    origin = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = allow_headers
    resp.headers["Access-Control-Expose-Headers"] = "Mcp-Session-Id, MCP-Protocol-Version"

    proto = request.headers.get("Mcp-Protocol-Version") or getattr(g, "mcp_protocol", None) or MCP_PROTOCOL_VERSION_FALLBACK
    resp.headers["MCP-Protocol-Version"] = proto
    log.info("RESP %s %s -> %s", request.method, request.path, resp.status)
    return resp

def _authz_check():
    if MCP_SHARED_KEY:
        key = request.headers.get("X-MCP-Key") or ""
        if key != MCP_SHARED_KEY:
            return jsonify({"jsonrpc":"2.0","id":None,"error":{"code":-32001,"message":"Unauthorized"}}), 200
    return None

@app.route("/", methods=["OPTIONS"])
@app.route("/mcp/tools", methods=["OPTIONS"])
def _options_ok():
    return ("", 204)

# -------------------- Tools descriptor --------------------
def tools_descriptor():
    tools = [
        # === Read tools ===
        {
            "name": "list_workspaces",
            "description": "List workspace IDs and names for a container.",
            "inputSchema": {"type":"object","properties":{"accountId":{"type":"string"},"containerId":{"type":"string"}},"required":["accountId","containerId"]}
        },
        {
            "name": "audit_container",
            "description": "Audit a GTM container and summarize GA4 tags/triggers with lint rules.",
            "inputSchema": {"type":"object","properties":{"accountId":{"type":"string"},"containerId":{"type":"string"},"workspaceId":{"type":"string"}},"required":["accountId","containerId"]}
        },

        # === Write tools (respect ALLOW_GTM_WRITES & optional dryRun) ===
        {
            "name": "create_ga4_config_tag",
            "description": "Create a GA4 Configuration tag in a GTM workspace.",
            "inputSchema": {
                "type":"object",
                "properties":{
                    "accountId":{"type":"string"},"containerId":{"type":"string"},"workspaceId":{"type":"string"},
                    "measurementId":{"type":"string"},"tagName":{"type":"string"},"sendPageView":{"type":"boolean"},
                    "dryRun":{"type":"boolean"}
                },
                "required":["accountId","containerId","workspaceId","measurementId"]
            }
        },
        {
            "name": "create_ga4_event_tag",
            "description": "Create a GA4 Event tag. Provide either measurementId OR a GA4 Config tag reference (configTagId or configTagName).",
            "inputSchema": {
                "type":"object",
                "properties":{
                    "accountId":{"type":"string"},"containerId":{"type":"string"},"workspaceId":{"type":"string"},
                    "eventName":{"type":"string"},"triggerIds":{"type":"array","items":{"type":"string"}},
                    "measurementId":{"type":"string"},"configTagId":{"type":"string"},"configTagName":{"type":"string"},
                    "eventParameters":{"type":"object"},"tagName":{"type":"string"},
                    "dryRun":{"type":"boolean"}
                },
                "required":["accountId","containerId","workspaceId","eventName","triggerIds"]
            }
        },
        {
            "name": "create_trigger",
            "description": "Create a GTM Trigger (Pageview, DOM Ready, Window Loaded, Custom Event, Click, Link Click, Form Submission, History Change, Timer, JS Error, Element Visibility, YouTube Video, Trigger Group). Supports filter_logic + up to 5 filters.",
            "inputSchema": {
                "type":"object",
                "properties":{
                    "accountId":{"type":"string"},"containerId":{"type":"string"},"workspaceId":{"type":"string"},
                    "type":{"type":"string"},"name":{"type":"string"},"triggerKey":{"type":"string"},
                    # Custom Event
                    "eventName":{"type":"string"},"useRegex":{"type":"boolean"},
                    # Link/Form
                    "waitForTags":{"type":"boolean"},"waitForTagsTimeout":{"type":"integer"},"checkValidation":{"type":"boolean"},
                    # Element Visibility
                    "selectionMethod":{"type":"string","enum":["CSS_SELECTOR","ID"]},
                    "selector":{"type":"string"},"elementId":{"type":"string"},
                    "minPercentVisible":{"type":"integer"},
                    "observeDomChanges":{"type":"boolean"},"fireOnce":{"type":"boolean"},
                    # YouTube
                    "captureStart":{"type":"boolean"},"captureComplete":{"type":"boolean"},
                    "capturePause":{"type":"boolean"},"captureProgress":{"type":"boolean"},
                    "progressThresholds":{"type":"array","items":{"type":"integer"}},
                    # Timer
                    "intervalMs":{"type":"integer"},"limit":{"type":"integer"},
                    # Trigger Group
                    "groupTriggerIds":{"type":"array","items":{"type":"string"}},
                    # Filters
                    "filterLogic":{"type":"string","enum":["ALL","ANY"]},
                    "filters":{"type":"array","items":{
                        "type":"object","properties":{"var":{"type":"string"},"op":{"type":"string"},"val":{"type":["string","number","boolean"]}},
                        "required":["var","op"]
                    }},
                    "dryRun":{"type":"boolean"}
                },
                "required":["accountId","containerId","workspaceId","type"]
            }
        },

        # === Batch import from CSV/Excel (server parses rows into tool calls) ===
        {
            "name": "batch_plan_from_csv",
            "description": "Parse CSV text following the template and return a dry-run plan (no writes).",
            "inputSchema": {"type":"object","properties":{"csvText":{"type":"string"}}, "required":["csvText"]}
        },
        {
            "name": "batch_apply_from_csv",
            "description": "Parse CSV text and apply in dependency order (Triggers -> GA4 Config -> GA4 Event). Respects dryRun in rows and ALLOW_GTM_WRITES.",
            "inputSchema": {"type":"object","properties":{"csvText":{"type":"string"}}, "required":["csvText"]}
        }
    ]
    return {"tools": tools}

# -------------------- Health & discovery --------------------
@app.route("/healthz", methods=["GET"], strict_slashes=False)
@app.route("/health", methods=["GET"], strict_slashes=False)
def healthz():
    return jsonify({"ok": True, "version": SERVER_VERSION}), 200

@app.get("/.well-known/mcp.json")
def mcp_discovery():
    d = {"mcpVersion":"1.0","name":SERVER_NAME,"version":SERVER_VERSION,"auth":{"type":"none"},"capabilities":{"tools":{"listChanged": True}}}
    d.update(tools_descriptor())
    return jsonify(d)

@app.route("/mcp/tools", methods=["GET"], strict_slashes=False)
def mcp_tools_index():
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

# -------------------- JSON-RPC root --------------------
@app.post("/", strict_slashes=False)
def root_post():
    # Optional shared-secret
    maybe = _authz_check()
    if maybe: return maybe

    t0 = time.time()
    payload = request.get_json(force=True) or {}
    log.info("ROOT POST payload keys=%s", list(payload.keys()))

    if payload.get("jsonrpc") == "2.0":
        rpc_id = payload.get("id", None)
        method = (payload.get("method") or "").lower()
        params = payload.get("params") or {}

        def rpc_result(result_obj, http=200):
            dt = int((time.time() - t0) * 1000)
            log.info("OK %s in %dms", method, dt)
            return jsonify({"jsonrpc": "2.0", "id": rpc_id, "result": result_obj}), http

        def rpc_error(code, message, data=None, http=200):
            dt = int((time.time() - t0) * 1000)
            log.warning("ERR %s in %dms: %s", method, dt, message)
            err = {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}
            if data is not None:
                err["error"]["data"] = data
            return jsonify(err), http

        if method == "initialize":
            client_proto = params.get("protocolVersion") or MCP_PROTOCOL_VERSION_FALLBACK
            g.mcp_protocol = client_proto
            result = {"protocolVersion": client_proto,"serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},"capabilities": {"tools": {"listChanged": True}}}
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
                # ---- list_workspaces ----
                if name == "list_workspaces":
                    svc = get_tagmanager_service()
                    a = args["accountId"]; c = args["containerId"]
                    parent = f"accounts/{a}/containers/{c}"
                    resp = svc.accounts().containers().workspaces().list(parent=parent).execute()
                    ws = [{"id": w.get("workspaceId"), "name": w.get("name",""), "description": w.get("description","")} for w in (resp.get("workspace", []) or [])]
                    return rpc_result(_ok_text("Workspaces", {"workspaces": ws}))

                # ---- audit_container (uses REST handler for same payload) ----
                if name == "audit_container":
                    body = {"action": "audit_container", "params": args}
                    with app.test_request_context(json=body):
                        resp = mcp_invoke()
                    data = resp.get_json() if hasattr(resp, "get_json") else None
                    if data and isinstance(data, dict) and data.get("ok") is False:
                        return rpc_result(_err_text("Audit failed", data))
                    return rpc_result(_ok_text("GTM audit summary", data.get("result", {})))

                # ---- create_ga4_config_tag ----
                if name == "create_ga4_config_tag":
                    _require_writes()
                    svc = get_tagmanager_service()
                    a=args["accountId"]; c=args["containerId"]; w=args["workspaceId"]
                    measurement_id = args["measurementId"]
                    send_page_view = bool(args.get("sendPageView", True))
                    tag_name = _sanitize_name(args.get("tagName") or f"GA4 Config - {measurement_id}")
                    dry = bool(args.get("dryRun", False))

                    parent = _ws_path(a,c,w)
                    body = {"name": tag_name, "type": GA4_CONFIG_TYPE, "parameter":[P_bool("sendPageView", send_page_view), P_template("measurementId", measurement_id)]}
                    if dry:
                        return rpc_result(_ok_text("[dryRun] Would create GA4 Config", {"parent": parent, "body": body}))
                    res = svc.accounts().containers().workspaces().tags().create(parent=parent, body=body).execute()
                    return rpc_result(_ok_text("GA4 Config tag created", res))

                # ---- create_ga4_event_tag ----
                if name == "create_ga4_event_tag":
                    _require_writes()
                    svc = get_tagmanager_service()
                    a=args["accountId"]; c=args["containerId"]; w=args["workspaceId"]
                    event_name = (args["eventName"] or "").strip()
                    if not event_name: return rpc_result(_err_text("eventName must be non-empty"))
                    trigger_ids_in = [str(t) for t in (args.get("triggerIds") or [])]
                    if not trigger_ids_in: return rpc_result(_err_text("'triggerIds' is required and must be a non-empty array"))

                    measurement_id = args.get("measurementId")
                    config_tag_id = args.get("configTagId")
                    config_tag_name = args.get("configTagName")
                    if not (measurement_id or config_tag_id or config_tag_name):
                        return rpc_result(_err_text("Provide either 'measurementId' or 'configTagId' or 'configTagName'"))

                    # Resolve configTagName -> tagId if needed
                    if (not measurement_id) and (not config_tag_id) and config_tag_name:
                        ws_path = _ws_path(a,c,w)
                        tags = svc.accounts().containers().workspaces().tags().list(parent=ws_path).execute().get("tag", []) or []
                        match = next((t for t in tags if (t.get("name") or "") == config_tag_name), None)
                        if not match:
                            return rpc_result(_err_text(f"configTagName '{config_tag_name}' not found"))
                        config_tag_id = match.get("tagId")

                    # Resolve trigger keys (strings not numeric) -> IDs
                    ws_path = _ws_path(a,c,w)
                    triggers_all = svc.accounts().containers().workspaces().triggers().list(parent=ws_path).execute().get("trigger", []) or []
                    id_by_key = { (t.get("name") or ""): str(t.get("triggerId")) for t in triggers_all }  # fallback map by name
                    resolved_triggers = []
                    for t in trigger_ids_in:
                        if re.fullmatch(r"\d+", t):
                            resolved_triggers.append(t)
                        else:
                            # Try to resolve by name (or friendly key you used as name)
                            tid = id_by_key.get(t)
                            if not tid:
                                return rpc_result(_err_text(f"trigger '{t}' not found by ID or name"))
                            resolved_triggers.append(tid)

                    tag_name = _sanitize_name(args.get("tagName") or f"GA4 Event - {event_name}")
                    ev_params = _event_parameters_list(args.get("eventParameters") or {})

                    params_list = [P_template("eventName", event_name)]
                    if measurement_id:
                        params_list.append(P_template("measurementId", measurement_id))
                    else:
                        params_list.append({"type": "tagReference", "key": "measurementId", "value": str(config_tag_id)})

                    if ev_params:
                        params_list.append(ev_params)

                    body = {"name": tag_name, "type": GA4_EVENT_TYPE, "firingTriggerId": resolved_triggers, "parameter": params_list}
                    if bool(args.get("dryRun", False)):
                        return rpc_result(_ok_text("[dryRun] Would create GA4 Event", {"parent": ws_path, "body": body}))

                    res = svc.accounts().containers().workspaces().tags().create(parent=ws_path, body=body).execute()
                    return rpc_result(_ok_text("GA4 Event tag created", res))

                # ---- create_trigger ----
                if name == "create_trigger":
                    _require_writes()
                    svc = get_tagmanager_service()
                    a=args["accountId"]; c=args["containerId"]; w=args.get("workspaceId")
                    ws_path, _ = resolve_workspace_path(svc, a, c, w)
                    t_in = (args.get("type") or "").strip().upper()
                    type_map = {
                        "PAGEVIEW":"pageview","DOM_READY":"domReady","WINDOW_LOADED":"windowLoaded","CUSTOM_EVENT":"customEvent",
                        "CLICK":"click","CLICK_ALL_ELEMENTS":"click","JUST_LINKS":"linkClick","LINK_CLICK":"linkClick",
                        "FORM_SUBMISSION":"formSubmission","HISTORY_CHANGE":"historyChange","TIMER":"timer","JAVASCRIPT_ERROR":"jsError",
                        "ELEMENT_VISIBILITY":"elementVisibility","YOUTUBE":"youTubeVideo","YOUTUBE_VIDEO":"youTubeVideo","TRIGGER_GROUP":"triggerGroup",
                    }
                    if t_in not in type_map:
                        return rpc_result(_err_text(f"Unsupported trigger type '{t_in}'"))
                    event_type = type_map[t_in]
                    trg_name = _sanitize_name(args.get("name") or f"{t_in.title()} Trigger")
                    dry = bool(args.get("dryRun", False))

                    body = {"name": trg_name, "type": event_type}

                    # Link/Form top-level props
                    if event_type in ("linkClick","formSubmission"):
                        if "waitForTags" in args:        body["waitForTags"] = bool(args["waitForTags"])
                        if "checkValidation" in args:    body["checkValidation"] = bool(args["checkValidation"])
                        if "waitForTagsTimeout" in args: body["waitForTagsTimeout"] = int(args["waitForTagsTimeout"])

                    # Element Visibility
                    if event_type == "elementVisibility":
                        sel = (args.get("selectionMethod") or "").upper()
                        if sel not in ("CSS_SELECTOR","ID"):
                            return rpc_result(_err_text("elementVisibility requires selectionMethod = CSS_SELECTOR or ID"))
                        params = [P_template("selectionMethod", sel)]
                        if sel == "CSS_SELECTOR":
                            selector = args.get("selector")
                            if not selector: return rpc_result(_err_text("elementVisibility (CSS_SELECTOR) requires 'selector'"))
                            params.append(P_template("elementSelector", selector))
                        else:
                            element_id = args.get("elementId")
                            if not element_id: return rpc_result(_err_text("elementVisibility (ID) requires 'elementId'"))
                            params.append(P_template("elementId", element_id))
                        if "minPercentVisible" in args: params.append(P_int("minPercentVisible", args["minPercentVisible"]))
                        if "observeDomChanges" in args: params.append(P_bool("observeDomChanges", args["observeDomChanges"]))
                        if "fireOnce" in args:          params.append(P_bool("fireOnce", args["fireOnce"]))
                        body["parameter"] = params

                    # Custom Event
                    if event_type == "customEvent":
                        ev = (args.get("eventName") or "").strip()
                        if not ev: return rpc_result(_err_text("customEvent requires 'eventName'"))
                        if bool(args.get("useRegex", False)):
                            body["parameter"] = [P_bool("useRegex", True), P_template("eventName", ev)]
                        else:
                            body["parameter"] = [P_template("eventName", ev)]

                    # YouTube
                    if event_type == "youTubeVideo":
                        params = []
                        params += [P_bool("captureStart",    bool(args.get("captureStart", True)))]
                        params += [P_bool("captureComplete", bool(args.get("captureComplete", True)))]
                        params += [P_bool("capturePause",    bool(args.get("capturePause", False)))]
                        params += [P_bool("captureProgress", bool(args.get("captureProgress", True)))]
                        thresholds = args.get("progressThresholds") or [10,25,50,75]
                        params.append(P_template("progressThresholds", ",".join(str(int(x)) for x in thresholds)))
                        body["parameter"] = params

                    # Timer
                    if event_type == "timer":
                        interval_ms = int(args.get("intervalMs") or args.get("interval") or 1000)
                        limit = int(args.get("limit") or 1)
                        body["parameter"] = [P_template("eventName","gtm.timer"), P_int("interval", interval_ms), P_int("limit", limit)]

                    # Trigger Group
                    if event_type == "triggerGroup":
                        ids = args.get("groupTriggerIds") or []
                        if not ids or len(ids) < 2:
                            return rpc_result(_err_text("triggerGroup requires 'groupTriggerIds' with 2+ trigger IDs"))
                        body["parameter"] = [P_trigger_refs("triggerIds", ids)]

                    # Filters
                    filters = args.get("filters") or []
                    filter_logic = (args.get("filterLogic") or "ALL").upper()
                    try:
                        _apply_filters_to_trigger_body(body, filters, filter_logic)
                    except Exception as e:
                        return rpc_result(_err_text("Invalid filters", {"message": str(e)}))

                    if dry:
                        return rpc_result(_ok_text("[dryRun] Would create Trigger", {"parent": ws_path, "body": body}))

                    res = svc.accounts().containers().workspaces().triggers().create(parent=ws_path, body=body).execute()
                    # If caller passed a 'triggerKey', you can store a mapping externally; for now we return it in the payload.
                    if args.get("triggerKey"):
                        res["_triggerKey"] = args.get("triggerKey")
                    return rpc_result(_ok_text(f"Trigger created ({event_type})", res))

                # ---- batch_plan_from_csv / batch_apply_from_csv ----
                if name in ("batch_plan_from_csv","batch_apply_from_csv"):
                    csv_text = args.get("csvText") or ""
                    if not csv_text.strip():
                        return rpc_result(_err_text("csvText must be non-empty"))
                    try:
                        import csv, io
                        reader = csv.DictReader(io.StringIO(csv_text))
                        rows = [dict(r) for r in reader]
                    except Exception as e:
                        return rpc_result(_err_text("Failed to parse CSV", {"message": str(e)}))

                    # Very simple planner: group by action, then materialize tool calls.
                    plan = {"counts":{}, "actions":[]}
                    for r in rows:
                        action = (r.get("action") or "").strip()
                        plan["counts"][action] = plan["counts"].get(action,0)+1
                        # Normalize booleans and lists
                        def b(s): return str(s).lower().strip()=="true"
                        def split_pipe(s): return [x.strip() for x in str(s or "").split("|") if x.strip()]
                        def kv_sc(s):
                            out = {}
                            for pair in str(s or "").split(";"):
                                if not pair.strip(): continue
                                k, _, v = pair.partition("=")
                                out[k.strip()] = v.strip()
                            return out

                        if action == "create_trigger":
                            filters = []
                            # up to 5 filters: filter_logic, filterN_var, filterN_op, filterN_val
                            logic = (r.get("filter_logic") or "ALL").upper()
                            for i in range(1,6):
                                var = r.get(f"filter{i}_var"); op = r.get(f"filter{i}_op"); val = r.get(f"filter{i}_val")
                                if var and op:
                                    filters.append({"var": var, "op": op, "val": val})
                            args_obj = {
                                "accountId": r.get("accountId"), "containerId": r.get("containerId"), "workspaceId": r.get("workspaceId"),
                                "type": r.get("triggerType"), "name": r.get("name"), "triggerKey": r.get("triggerKey"),
                                "waitForTags": b(r.get("waitForTags")), "waitForTagsTimeout": int(r.get("waitForTagsTimeout") or 0) or None,
                                "checkValidation": b(r.get("checkValidation")),
                                "selectionMethod": r.get("selectionMethod"), "selector": r.get("selector"), "elementId": r.get("elementId"),
                                "minPercentVisible": int(r.get("minPercentVisible") or 0) or None,
                                "observeDomChanges": b(r.get("observeDomChanges")), "fireOnce": b(r.get("fireOnce")),
                                "captureStart": b(r.get("captureStart")), "captureComplete": b(r.get("captureComplete")),
                                "capturePause": b(r.get("capturePause")), "captureProgress": b(r.get("captureProgress")),
                                "progressThresholds": split_pipe(r.get("progressThresholds") or ""),
                                "intervalMs": int(r.get("intervalMs") or 0) or None, "limit": int(r.get("limit") or 0) or None,
                                "groupTriggerIds": split_pipe(r.get("groupTriggerIds") or ""),
                                "filterLogic": logic, "filters": filters,
                                "dryRun": b(r.get("dryRun")),
                            }
                            plan["actions"].append({"tool":"create_trigger","arguments":{k:v for k,v in args_obj.items() if v not in (None,"")}})
                        elif action == "create_ga4_config_tag":
                            args_obj = {
                                "accountId": r.get("accountId"), "containerId": r.get("containerId"), "workspaceId": r.get("workspaceId"),
                                "measurementId": r.get("measurementId"), "tagName": r.get("name"),
                                "sendPageView": b(r.get("sendPageView")), "dryRun": b(r.get("dryRun")),
                            }
                            plan["actions"].append({"tool":"create_ga4_config_tag","arguments":args_obj})
                        elif action == "create_ga4_event_tag":
                            trig_ids = split_pipe(r.get("triggerIds"))
                            args_obj = {
                                "accountId": r.get("accountId"), "containerId": r.get("containerId"), "workspaceId": r.get("workspaceId"),
                                "eventName": r.get("eventName"), "tagName": r.get("name"),
                                "triggerIds": trig_ids,
                                "eventParameters": kv_sc(r.get("eventParameters")),
                                "measurementId": r.get("measurementId"),
                                "configTagId": r.get("configTagId"),
                                "configTagName": r.get("configTagName"),
                                "dryRun": b(r.get("dryRun")),
                            }
                            plan["actions"].append({"tool":"create_ga4_event_tag","arguments":args_obj})
                        else:
                            plan["actions"].append({"tool":"(unsupported)", "arguments":{"row": r}})

                    if name == "batch_plan_from_csv":
                        return rpc_result(_ok_text("Batch dry-run plan (no writes)", plan))

                    # name == batch_apply_from_csv
                    _require_writes()
                    svc = get_tagmanager_service()
                    results = {"ok": True, "applied": [], "errors": []}

                    # 1) Create triggers first
                    for a in [x for x in plan["actions"] if x["tool"]=="create_trigger"]:
                        try:
                            with app.test_request_context(json={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_trigger","arguments":a["arguments"]}}):
                                resp = root_post()
                            data = resp.get_json()
                            results["applied"].append({"tool":"create_trigger","result": data})
                        except Exception as e:
                            results["errors"].append({"tool":"create_trigger","error": str(e)})

                    # 2) GA4 Config
                    for a in [x for x in plan["actions"] if x["tool"]=="create_ga4_config_tag"]:
                        try:
                            with app.test_request_context(json={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_ga4_config_tag","arguments":a["arguments"]}}):
                                resp = root_post()
                            data = resp.get_json()
                            results["applied"].append({"tool":"create_ga4_config_tag","result": data})
                        except Exception as e:
                            results["errors"].append({"tool":"create_ga4_config_tag","error": str(e)})

                    # 3) GA4 Events
                    for a in [x for x in plan["actions"] if x["tool"]=="create_ga4_event_tag"]:
                        try:
                            with app.test_request_context(json={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_ga4_event_tag","arguments":a["arguments"]}}):
                                resp = root_post()
                            data = resp.get_json()
                            results["applied"].append({"tool":"create_ga4_event_tag","result": data})
                        except Exception as e:
                            results["errors"].append({"tool":"create_ga4_event_tag","error": str(e)})

                    return rpc_result(_ok_text("Batch apply complete", results))

                # ---- Fallback ----
                return rpc_result(_err_text(f"Unsupported tool '{name}'"))

            except ValueError as ve:
                return rpc_result(_err_text("Invalid input", {"message": str(ve)}))
            except Exception as e:
                log.exception("Error in tools/call")
                return rpc_result(_err_text("Tool call failed", _gtm_error_payload(f"tools/call.{name}", e)))

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
        with app.test_request_context(json={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name": name, "arguments": args}}):
            return root_post()
    if t in ("ping", "health", "heartbeat"):
        return jsonify({"ok": True}), 200

    return jsonify({"ok": True, "echo": payload}), 200

# -------------------- REST convenience: /mcp/invoke (kept) --------------------
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

            rules = []
            # Rule: GA4 config presence
            if len(ga4_config) == 0:
                rules.append({"id":"R1","severity":"WARN","title":"No GA4 Config tag","finding":"0 GA4 Config tags found","suggestedFix":"Create GA4 Config tag with measurementId."})
            if len(ga4_config) > 1:
                rules.append({"id":"R2","severity":"ERR","title":"Multiple GA4 Config tags","finding":f"{len(ga4_config)} config tags","suggestedFix":"Consolidate to a single config or scope carefully."})

            # Rule: GA4 events sanity
            for t in ga4_events:
                en = event_name(t)
                trig = t.get("firingTriggerId") or []
                has_meas = any(p.get("key")=="measurementId" for p in (t.get("parameter") or []))
                if not trig:
                    rules.append({"id":"R3","severity":"ERR","title":"GA4 Event missing triggers","finding":f"event={en} has no firingTriggerId","suggestedFix":"Attach at least one trigger."})
                if not has_meas and not ga4_config:
                    rules.append({"id":"R4","severity":"ERR","title":"GA4 Event lacks measurement source","finding":f"event={en} without measurementId and no Config present","suggestedFix":"Add measurementId or create Config and reference it."})

            summary = {
                "container": {"accountId": account_id, "containerId": container_id, "workspacePath": ws_path},
                "counts": {"tags": len(tags), "triggers": len(triggers), "variables": len(variables), "ga4_config_tags": len(ga4_config), "ga4_event_tags": len(ga4_events)},
                "ga4": {"has_config": len(ga4_config) > 0, "events": [{"name": event_name(t), "tagId": t.get("tagId")} for t in ga4_events]},
                "triggers": [{"name": tr.get("name"), "type": tr.get("type"), "triggerId": tr.get("triggerId")} for tr in triggers],
                "rules": rules,
            }
            return jsonify({"ok": True, "result": summary})

        # Proxy JSON-RPC tools through for convenience
        if action in ("create_ga4_config_tag","create_ga4_event_tag","create_trigger","list_workspaces","batch_plan_from_csv","batch_apply_from_csv"):
            payload = {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name": action, "arguments": params}}
            with app.test_request_context(json=payload):
                return root_post()

        return jsonify({"ok": False, "error": f"Unsupported action '{action}'"}), 400

    except Exception as e:
        log.exception("Error in /mcp/invoke")
        return jsonify({"ok": False, "error": str(e)}), 500

# -------------------- Routes inspector --------------------
@app.get("/__routes")
def routes():
    return jsonify(sorted([str(r) for r in app.url_map.iter_rules()]))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
