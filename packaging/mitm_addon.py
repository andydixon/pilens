"""PiLens mitmdump addon.

Emits one JSON line per HTTP(S) transaction (and per client TLS failure) to
PILENS_FLOWS. Request/response bodies are written to PILENS_BODIES only when
PILENS_CAPTURE_BODIES=1, size-limited by PILENS_MAX_BODY_KB. Sensitive content
is therefore off by default.

This runs inside the pilens-proxy service's venv; it is not imported anywhere else.
"""
import json
import os
import time

FLOWS = os.environ.get("PILENS_FLOWS", "/var/lib/pilens/proxy/flows.ndjson")
BODIES = os.environ.get("PILENS_BODIES", "/var/lib/pilens/proxy/bodies")
CAPTURE_BODIES = os.environ.get("PILENS_CAPTURE_BODIES", "0") == "1"
MAX_BODY = int(os.environ.get("PILENS_MAX_BODY_KB", "256")) * 1024


def _emit(obj):
    try:
        with open(FLOWS, "a") as f:
            f.write(json.dumps(obj, separators=(",", ":")) + "\n")
            f.flush()
    except Exception:
        pass


def _headers(msg):
    out = {}
    for k, v in msg.headers.items(multi=True):
        out[k] = (out[k] + ", " + v) if k in out else v
    return out


def _write_body(flow_id, which, content):
    if not CAPTURE_BODIES or not content:
        return False
    data = content[:MAX_BODY]
    try:
        os.makedirs(BODIES, exist_ok=True)
        with open(os.path.join(BODIES, "%s.%s" % (flow_id, which)), "wb") as f:
            f.write(data)
        return True
    except Exception:
        return False


def _client(flow):
    try:
        return flow.client_conn.peername[0]
    except Exception:
        return ""


def _tls(flow):
    cc = flow.client_conn
    sc = flow.server_conn
    ver = getattr(cc, "tls_version", None) or getattr(sc, "tls_version", None) or ""
    alpn = getattr(cc, "alpn", b"") or b""
    try:
        alpn = alpn.decode()
    except Exception:
        alpn = str(alpn)
    return ver, getattr(cc, "sni", None) or "", alpn


class PiLens:
    def response(self, flow):
        req, resp = flow.request, flow.response
        ver, sni, alpn = _tls(flow)
        dur = 0
        try:
            dur = int((resp.timestamp_end - req.timestamp_start) * 1000)
        except Exception:
            pass
        has_req = _write_body(flow.id, "req", req.raw_content)
        has_resp = _write_body(flow.id, "resp", resp.raw_content)
        _emit({
            "id": flow.id,
            "ts": req.timestamp_start or time.time(),
            "client": _client(flow),
            "method": req.method,
            "scheme": req.scheme,
            "host": req.pretty_host,
            "port": req.port,
            "path": req.path,
            "http_version": resp.http_version,
            "status": resp.status_code,
            "reason": resp.reason or "",
            "req_ctype": req.headers.get("content-type", ""),
            "resp_ctype": resp.headers.get("content-type", ""),
            "req_size": len(req.raw_content or b""),
            "resp_size": len(resp.raw_content or b""),
            "duration_ms": dur,
            "tls_version": ver,
            "sni": sni,
            "alpn": alpn,
            "intercepted": req.scheme == "https",
            "error": "",
            "websocket": bool(flow.websocket),
            "has_req_body": has_req,
            "has_resp_body": has_resp,
            "req_headers": _headers(req),
            "resp_headers": _headers(resp),
        })

    def error(self, flow):
        try:
            req = flow.request
            ver, sni, alpn = _tls(flow)
            _emit({
                "id": flow.id,
                "ts": (req.timestamp_start if req else None) or time.time(),
                "client": _client(flow),
                "method": req.method if req else "",
                "scheme": req.scheme if req else "",
                "host": req.pretty_host if req else "",
                "port": req.port if req else 0,
                "path": req.path if req else "",
                "status": 0,
                "tls_version": ver,
                "sni": sni,
                "alpn": alpn,
                "intercepted": False,
                "error": str(flow.error) if flow.error else "connection error",
                "req_headers": {},
                "resp_headers": {},
            })
        except Exception:
            pass

    def tls_failed_client(self, data):
        # The device refused our certificate: it does not trust the CA, or the
        # app pins a specific certificate. Reported honestly, never bypassed.
        try:
            conn = data.conn
            peer = conn.peername[0] if conn.peername else ""
            sni = getattr(data.context.client, "sni", None) or getattr(conn, "sni", None) or ""
            _emit({
                "id": "tlsfail-%s-%d" % (peer.replace(".", "_").replace(":", "_"), int(time.time() * 1000) % 1000000000),
                "ts": time.time(),
                "client": peer,
                "scheme": "https",
                "host": sni,
                "sni": sni,
                "status": 0,
                "intercepted": False,
                "error": "client TLS failure: device does not trust the PiLens CA, or the app pins its own certificate",
                "req_headers": {},
                "resp_headers": {},
            })
        except Exception:
            pass


addons = [PiLens()]
