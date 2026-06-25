import os
import json
import queue
import threading

import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_lines
import ida_nalt
import ida_ida
import ida_bytes
import ida_name
import ida_segment
import ida_typeinf
import ida_gdl
import idautils

try:
    import ida_hexrays
    _HAS_HEXRAYS = ida_hexrays.init_hexrays_plugin()
except Exception:
    _HAS_HEXRAYS = False

from flask import Flask, jsonify, request, Response, send_from_directory

HOST = "0.0.0.0"
PORT = 8765
AUTH_TOKEN = "CreateUrOwnToken"
WEB_ROOT = ""
ALLOW_WRITE = True  # set False to refuse rename/comment edits (jumpto is always allowed)

def on_main_thread(query, flags=ida_kernwin.MFF_READ):
    result = {}

    def runner():
        try:
            result["value"] = query()
        except Exception as error:
            result["error"] = str(error)
        return 1

    ida_kernwin.execute_sync(runner, flags)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result.get("value")

def _build_color_map():
    pairs = [
        ("COLOR_INSN", "insn"),
        ("COLOR_REG", "reg"),
        ("COLOR_NUMBER", "num"),
        ("COLOR_STRING", "str"),
        ("COLOR_CHAR", "char"),
        ("COLOR_LOCNAME", "locvar"),
        ("COLOR_KEYWORD", "keyword"),
        ("COLOR_CODNAME", "codename"),
        ("COLOR_DATNAME", "dataname"),
        ("COLOR_DNAME", "dataname"),
        ("COLOR_IMPNAME", "impname"),
        ("COLOR_LIBNAME", "libname"),
        ("COLOR_SEGNAME", "segname"),
        ("COLOR_CREF", "cref"),
        ("COLOR_DREF", "dref"),
        ("COLOR_SYMBOL", "symbol"),
        ("COLOR_PREFIX", "prefix"),
        ("COLOR_AUTOCMT", "comment"),
        ("COLOR_REGCMT", "comment"),
        ("COLOR_RPTCMT", "comment"),
        ("COLOR_VOIDOP", "voidop"),
        ("COLOR_ERROR", "error"),
    ]
    mapping = {}
    for ida_const, css_class in pairs:
        value = getattr(ida_lines, ida_const, None)
        if value is not None:
            mapping[value] = css_class
    return mapping

_COLOR_MAP = _build_color_map()
_SCOLOR_ON = ida_lines.SCOLOR_ON
_SCOLOR_OFF = ida_lines.SCOLOR_OFF
_SCOLOR_ESC = ida_lines.SCOLOR_ESC
_SCOLOR_INV = ida_lines.SCOLOR_INV
_SCOLOR_ADDR = ida_lines.SCOLOR_ADDR
_ADDR_SIZE = ida_lines.COLOR_ADDR_SIZE

def _parse_tagged(line):
    tokens = []
    stack = ["default"]
    buffer = []

    def flush():
        if buffer:
            tokens.append({"t": "".join(buffer), "c": stack[-1]})
            buffer.clear()

    index = 0
    length = len(line)
    while index < length:
        char = line[index]
        if char == _SCOLOR_ON:
            flush()
            index += 1
            tag = line[index] if index < length else ""
            index += 1
            if tag == _SCOLOR_ADDR:
                index += _ADDR_SIZE
            else:
                stack.append(_COLOR_MAP.get(ord(tag), "default") if tag else "default")
        elif char == _SCOLOR_OFF:
            flush()
            index += 2
            if len(stack) > 1:
                stack.pop()
        elif char == _SCOLOR_ESC:
            index += 1
            if index < length:
                buffer.append(line[index])
                index += 1
        elif char == _SCOLOR_INV:
            index += 1
        else:
            buffer.append(char)
            index += 1
    flush()
    return tokens

def parse_tagged(line):
    try:
        return _parse_tagged(line)
    except Exception:
        return [{"t": ida_lines.tag_remove(line), "c": "default"}]

def hexea(ea):
    return "0x%X" % (ea & 0xFFFFFFFFFFFFFFFF)

def parse_ea(value):
    return int(value, 16)

_event_subscribers = set()
_event_lock = threading.Lock()

def publish_event(event):
    data = json.dumps(event)
    with _event_lock:
        for subscriber in list(_event_subscribers):
            subscriber.put(data)

def _build_view_map():
    pairs = [
        ("BWN_DISASM", "disasm"),
        ("BWN_PSEUDOCODE", "pseudo"),
        ("BWN_HEXVIEW", "hex"),
        ("BWN_STRINGS", "strings"),
        ("BWN_NAMES", "names"),
        ("BWN_IMPORTS", "imports"),
        ("BWN_EXPORTS", "exports"),
        ("BWN_SEGS", "segments"),
        ("BWN_LOCTYPS", "types"),
    ]
    mapping = {}
    for const, view in pairs:
        value = getattr(ida_kernwin, const, None)
        if value is not None:
            mapping[value] = view
    return mapping

_VIEW_MAP = _build_view_map()

_TITLE_HINTS = [("local types", "types")]

def _widget_view(widget):
    if widget is None:
        return None
    try:
        view = _VIEW_MAP.get(ida_kernwin.get_widget_type(widget))
        if view:
            return view
        # Fallback by window title for types whose BWN_* constant varies by version.
        title = (ida_kernwin.get_widget_title(widget) or "").lower()
        for hint, mapped in _TITLE_HINTS:
            if hint in title:
                return mapped
    except Exception:
        return None
    return None

class _ScreenHooks(ida_kernwin.UI_Hooks):
    def screen_ea_changed(self, ea, prev_ea):
        try:
            publish_event({"type": "screen_ea", "ea": hexea(ea)})
        except Exception:
            pass

    def current_widget_changed(self, widget, prev_widget):
        try:
            view = _widget_view(widget)
            if view:
                publish_event({"type": "view", "view": view})
        except Exception:
            pass

_screen_hooks = None

def query_info():
    try:
        bits = 64 if ida_ida.inf_is_64bit() else (16 if ida_ida.inf_is_16bit() else 32)
    except Exception:
        bits = 0
    return {
        "file": ida_nalt.get_root_filename(),
        "processor": ida_ida.inf_get_procname(),
        "bits": bits,
        "image_base": hexea(ida_nalt.get_imagebase()),
        "has_hexrays": bool(_HAS_HEXRAYS),
    }

def query_functions():
    functions = []
    for start_ea in idautils.Functions():
        func = ida_funcs.get_func(start_ea)
        functions.append(
            {
                "ea": hexea(start_ea),
                "name": ida_funcs.get_func_name(start_ea),
                "size": (func.end_ea - func.start_ea) if func else 0,
            }
        )
    return functions

def query_disassembly(ea):
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    lines = []
    for head in idautils.FuncItems(func.start_ea):
        tagged = ida_lines.generate_disasm_line(head, 0) or ""
        lines.append({"ea": hexea(head), "tokens": parse_tagged(tagged)})
    return {"ea": hexea(func.start_ea), "name": ida_funcs.get_func_name(func.start_ea), "lines": lines}

def query_graph(ea):
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    flow = ida_gdl.FlowChart(func, flags=ida_gdl.FC_PREDS)
    blocks = []
    edges = []
    for block in flow:
        lines = []
        head = block.start_ea
        while head < block.end_ea and head != ida_idaapi.BADADDR:
            tagged = ida_lines.generate_disasm_line(head, 0) or ""
            lines.append({"ea": hexea(head), "tokens": parse_tagged(tagged)})
            head = ida_bytes.get_item_end(head)
        successors = list(block.succs())
        for succ in successors:
            if len(successors) == 2:
                kind = "false" if succ.start_ea == block.end_ea else "true"
            else:
                kind = "uncond"
            edges.append({"src": block.id, "dst": succ.id, "kind": kind})
        blocks.append(
            {
                "id": block.id,
                "start": hexea(block.start_ea),
                "end": hexea(block.end_ea),
                "lines": lines,
            }
        )
    return {
        "ea": hexea(func.start_ea),
        "name": ida_funcs.get_func_name(func.start_ea),
        "blocks": blocks,
        "edges": edges,
    }

def query_pseudocode(ea):
    if not _HAS_HEXRAYS:
        return None
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    decompiled = ida_hexrays.decompile(func.start_ea)
    if decompiled is None:
        return None
    lines = [{"tokens": parse_tagged(item.line)} for item in decompiled.get_pseudocode()]
    return {"ea": hexea(func.start_ea), "name": ida_funcs.get_func_name(func.start_ea), "lines": lines}

def query_xrefs(ea):
    references = []
    for xref in idautils.XrefsTo(ea):
        references.append(
            {
                "frm": hexea(xref.frm),
                "name": ida_funcs.get_func_name(xref.frm) or "",
                "is_call": bool(xref.iscode),
            }
        )
    return references

def query_strings():
    items = []
    for string_item in idautils.Strings():
        items.append({"ea": hexea(string_item.ea), "length": string_item.length, "text": str(string_item)})
        if len(items) >= 50000:
            break
    return items

def query_imports():
    items = []
    for module_index in range(ida_nalt.get_import_module_qty()):
        module_name = ida_nalt.get_import_module_name(module_index) or ""

        def collect(ea, name, ordinal, _module=module_name):
            items.append({"ea": hexea(ea), "module": _module, "name": name or "", "ordinal": ordinal or 0})
            return True

        ida_nalt.enum_import_names(module_index, collect)
    return items

def query_exports():
    items = []
    for _index, ordinal, ea, name in idautils.Entries():
        items.append({"ea": hexea(ea), "ordinal": ordinal, "name": name or ""})
    return items

def query_hex(ea, count):
    count = max(0, min(int(count), 0x10000))
    data = ida_bytes.get_bytes(ea, count) or b""
    return {"ea": hexea(ea), "hex": data.hex()}

def query_segments():
    items = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        items.append(
            {
                "start": hexea(seg.start_ea),
                "end": hexea(seg.end_ea),
                "name": ida_segment.get_segm_name(seg),
                "class": ida_segment.get_segm_class(seg) or "",
                "perm": seg.perm,
            }
        )
    return items

def query_names():
    items = []
    for ea, name in idautils.Names():
        items.append({"ea": hexea(ea), "name": name})
        if len(items) >= 50000:
            break
    return items

def query_local_types():
    items = []
    try:
        til = ida_typeinf.get_idati()
        try:
            count = ida_typeinf.get_ordinal_count(til)
        except Exception:
            count = ida_typeinf.get_ordinal_qty(til)
        for ordinal in range(1, count + 1):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            name = tif.get_type_name() or ""
            try:
                decl = tif._print(name or None, ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_TYPE)
            except Exception:
                decl = ""
            items.append({"ordinal": ordinal, "name": name, "decl": decl or str(tif)})
    except Exception as error:
        return {"error": str(error), "items": []}
    return {"items": items}

app = Flask(__name__, static_folder=None)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.before_request
def check_auth():
    if request.method == "OPTIONS":
        return
    if AUTH_TOKEN and request.path.startswith("/api"):
        if request.headers.get("Authorization", "") == f"Bearer {AUTH_TOKEN}":
            return
        if request.args.get("token", "") == AUTH_TOKEN:
            return
        return Response("unauthorized", status=401)

@app.route("/api/info")
def route_info():
    return jsonify(on_main_thread(query_info))

@app.route("/api/functions")
def route_functions():
    return jsonify(on_main_thread(query_functions))

@app.route("/api/disasm/<ea>")
def route_disasm(ea):
    address = parse_ea(ea)
    result = on_main_thread(lambda: query_disassembly(address))
    return jsonify(result) if result else Response("no function at address", status=404)

@app.route("/api/graph/<ea>")
def route_graph(ea):
    address = parse_ea(ea)
    result = on_main_thread(lambda: query_graph(address))
    return jsonify(result) if result else Response("no function at address", status=404)

@app.route("/api/pseudocode/<ea>")
def route_pseudocode(ea):
    address = parse_ea(ea)
    result = on_main_thread(lambda: query_pseudocode(address), ida_kernwin.MFF_WRITE)
    return jsonify(result) if result else Response("pseudocode unavailable", status=404)

@app.route("/api/xrefs/<ea>")
def route_xrefs(ea):
    return jsonify(on_main_thread(lambda: query_xrefs(parse_ea(ea))))

@app.route("/api/strings")
def route_strings():
    return jsonify(on_main_thread(query_strings))

@app.route("/api/imports")
def route_imports():
    return jsonify(on_main_thread(query_imports))

@app.route("/api/exports")
def route_exports():
    return jsonify(on_main_thread(query_exports))

@app.route("/api/hex/<ea>")
def route_hex(ea):
    address = parse_ea(ea)
    count = request.args.get("count", default=1024, type=int)
    return jsonify(on_main_thread(lambda: query_hex(address, count)))

@app.route("/api/segments")
def route_segments():
    return jsonify(on_main_thread(query_segments))

@app.route("/api/names")
def route_names():
    return jsonify(on_main_thread(query_names))

@app.route("/api/local-types")
def route_local_types():
    return jsonify(on_main_thread(query_local_types))

@app.route("/api/events")
def route_events():
    def stream():
        subscriber = queue.Queue()
        with _event_lock:
            _event_subscribers.add(subscriber)
        try:
            current = on_main_thread(lambda: hexea(ida_kernwin.get_screen_ea()))
            yield "data: %s\n\n" % json.dumps({"type": "screen_ea", "ea": current})
            while True:
                try:
                    yield "data: %s\n\n" % subscriber.get(timeout=15)
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            with _event_lock:
                _event_subscribers.discard(subscriber)

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return Response(stream(), mimetype="text/event-stream", headers=headers)

@app.route("/api/goto", methods=["POST"])
def route_goto():
    ea = parse_ea(request.get_json(force=True).get("ea"))
    on_main_thread(lambda: ida_kernwin.jumpto(ea))
    return jsonify({"ok": True})

@app.route("/api/rename", methods=["POST"])
def route_rename():
    if not ALLOW_WRITE:
        return Response("writes disabled", status=403)
    data = request.get_json(force=True)
    ea = parse_ea(data.get("ea"))
    name = data.get("name") or ""

    def do_rename():
        ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN)
        return {"ok": bool(ok), "name": ida_name.get_name(ea) or ""}

    return jsonify(on_main_thread(do_rename, ida_kernwin.MFF_WRITE))

@app.route("/api/comment", methods=["POST"])
def route_comment():
    if not ALLOW_WRITE:
        return Response("writes disabled", status=403)
    data = request.get_json(force=True)
    ea = parse_ea(data.get("ea"))
    text = data.get("text") or ""
    repeatable = bool(data.get("repeatable", False))

    def do_comment():
        ida_bytes.set_cmt(ea, text, repeatable)
        return {"ok": True}

    return jsonify(on_main_thread(do_comment, ida_kernwin.MFF_WRITE))

LANDING_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>idarem</title>
<style>body{background:#0b0b0d;color:#e6e6ea;font-family:system-ui;max-width:660px;margin:60px auto;
padding:0 20px;line-height:1.6}code{background:#1d1d22;padding:2px 6px;border-radius:4px}a{color:#9bb8e8}</style>
</head><body><h2>idarem</h2>
<p>The API server is running &mdash; this address serves the data, not the UI.</p>
<p><b>To see the web client, either:</b></p>
<ul>
<li>build it (<code>cd web &amp;&amp; npm run build</code>), set <code>WEB_ROOT</code> in <code>idarem.py</code>
to the <code>web/dist</code> path, and reload the plugin &mdash; the UI is then served right here; or</li>
<li>run it in dev mode (<code>cd web &amp;&amp; npm run dev</code>) and point it at this address.</li>
</ul>
<p>API endpoints: <code>/api/info</code>, <code>/api/functions</code>, <code>/api/disasm/&lt;ea&gt;</code>,
<code>/api/pseudocode/&lt;ea&gt;</code>, <code>/api/xrefs/&lt;ea&gt;</code></p></body></html>"""

def resolve_web_root():
    if WEB_ROOT:
        return WEB_ROOT
    env_root = os.environ.get("IDAREM_WEB_ROOT", "")
    if env_root and os.path.isdir(env_root):
        return env_root
    guess = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web", "dist"))
    return guess if os.path.isdir(guess) else ""

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_web(path):
    if path.startswith("api"):
        return Response("not found", status=404)
    root = resolve_web_root()
    if root:
        if path and os.path.isfile(os.path.join(root, path)):
            return send_from_directory(root, path)
        return send_from_directory(root, "index.html")
    return Response(LANDING_PAGE, mimetype="text/html")

_server_thread = None

def start_server():
    global _server_thread, _screen_hooks
    if _screen_hooks is None:
        _screen_hooks = _ScreenHooks()
        _screen_hooks.hook()
    if _server_thread is not None and _server_thread.is_alive():
        print(f"[idarem] already serving on port {PORT}")
        return

    def serve():
        app.run(host=HOST, port=PORT, threaded=True, use_reloader=False)

    _server_thread = threading.Thread(target=serve, name="idarem", daemon=True)
    _server_thread.start()
    print(f"[idarem] serving on http://{HOST}:{PORT}  (hexrays={'yes' if _HAS_HEXRAYS else 'no'})")
    if not AUTH_TOKEN:
        print(
            "[idarem] WARNING: AUTH_TOKEN is empty — the API is UNAUTHENTICATED. "
            "Because responses send 'Access-Control-Allow-Origin: *', any website your "
            "browser visits can read this database while the server runs. Set AUTH_TOKEN "
            "(and prefer a tunnel over binding a public port) before exposing it."
        )

class IdaRemotePlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Serve IDA analysis over HTTP for a remote web client"
    help = ""
    wanted_name = "idarem"
    wanted_hotkey = "Ctrl-Alt-R"

    def init(self):
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        start_server()

    def term(self):
        global _screen_hooks
        if _screen_hooks is not None:
            _screen_hooks.unhook()
            _screen_hooks = None

def PLUGIN_ENTRY():
    return IdaRemotePlugin()