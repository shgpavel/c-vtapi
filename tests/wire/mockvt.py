#!/usr/bin/env python3
"""Recording mock of the VirusTotal v2 API.

Every request is appended to the log as one JSON line (method, path, ordered
query pairs, content type, decoded form / multipart body).  Responses come
from a JSON config:

  {"routes": {"GET /vtapi/v2/ip-address/report": [resp, resp, ...],
              "* /vtapi/v2/file/scan": [resp]},
   "default": resp}

resp = {"status": 200, "json": {...}} | {"body": "text"} | {"body_b64": "..."}
       plus optional "headers": {...}, "delay": seconds.
Responses for a route are consumed in order; the last one repeats.

  {"drop": true}      log the request, then close the connection without
                      sending any response (curl: "Empty reply from server").
  "{MOCK}"            in "json" values, "body" and header values is replaced
                      by the mock's own origin, http://127.0.0.1:<port>
                      (absolute upload_url, redirect Locations).
  "chunks": N         send the body with Transfer-Encoding: chunked in N
                      pieces (exercises client-side body concatenation).
  "ctype": "..."      override the response Content-Type.

run.py uses MockServer in-process.  Standalone (for debugging):
  mockvt.py --config config.json --log requests.jsonl [--port 0]
prints the port it listens on.
"""
import argparse
import base64
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

sys.dont_write_bytecode = True  # keep the source tree clean
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_util import blob  # noqa: E402

HDR_DROP = {"host", "user-agent", "content-length", "accept", "expect",
            "transfer-encoding", "connection", "content-type"}


def parse_multipart(body: bytes, boundary: str):
    parts = []
    delim = b"--" + boundary.encode()
    for chunk in body.split(delim)[1:]:
        if chunk.startswith(b"--"):
            break
        chunk = chunk[2:] if chunk.startswith(b"\r\n") else chunk
        head, _, data = chunk.partition(b"\r\n\r\n")
        if data.endswith(b"\r\n"):
            data = data[:-2]
        p = {}
        for line in head.decode("latin-1").split("\r\n"):
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k == "content-disposition":
                for item in v.split(";")[1:]:
                    ik, _, iv = item.strip().partition("=")
                    p[ik] = iv.strip('"')
            elif k == "content-type":
                p["content_type"] = v.strip()
        p["data"] = blob(data)
        parts.append(p)
    return parts


def ctype_params(ct: str):
    base, *rest = [s.strip() for s in ct.split(";")]
    params = {}
    for r in rest:
        k, _, v = r.partition("=")
        params[k.lower()] = v.strip('"')
    return base.lower(), params


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60

    def log_message(self, *a):
        pass

    def setup(self):
        super().setup()
        self._pending = True
        self.server.track(+1)

    def finish(self):
        if self._pending:
            self._pending = False
            self.server.track(-1)
        super().finish()

    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            out = b""
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return out, True
                out += self.rfile.read(size)
                self.rfile.readline()
        n = int(self.headers.get("Content-Length") or 0)
        return (self.rfile.read(n) if n else b""), False

    def handle_any(self):
        srv = self.server
        u = urlsplit(self.path)
        body, chunked = self.read_body()
        rec = {"method": self.command, "path": u.path,
               "query": parse_qsl(u.query, keep_blank_values=True),
               "headers": {k.lower(): v for k, v in self.headers.items()
                           if k.lower() not in HDR_DROP}}
        ct = self.headers.get("Content-Type")
        if ct:
            base, params = ctype_params(ct)
            rec["content_type"] = base
            if base == "multipart/form-data":
                rec["multipart"] = parse_multipart(body, params.get("boundary", ""))
            elif base == "application/x-www-form-urlencoded":
                rec["form"] = parse_qsl(body.decode("latin-1"), keep_blank_values=True)
            elif body:
                rec["body"] = blob(body)
        elif body:
            rec["body"] = blob(body)
        if chunked:
            rec["chunked"] = True
        resp = srv.record(rec, f"{self.command} {u.path}", f"* {u.path}")
        self._pending = False
        srv.track(-1)

        if resp.get("delay"):
            time.sleep(resp["delay"])
        if resp.get("drop"):
            self.close_connection = True
            return
        origin = srv.origin
        if "json" in resp:
            data = json.dumps(resp["json"]).replace("{MOCK}", origin).encode()
            ctype = "application/json"
        elif "body_b64" in resp:
            data = base64.b64decode(resp["body_b64"])
            ctype = "application/octet-stream"
        else:
            data = resp.get("body", "").replace("{MOCK}", origin).encode()
            ctype = "text/plain"
        ctype = resp.get("ctype", ctype)
        chunks = int(resp.get("chunks", 0))
        self.send_response(resp.get("status", 200))
        self.send_header("Content-Type", ctype)
        if chunks > 0:
            self.send_header("Transfer-Encoding", "chunked")
        else:
            self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        for k, v in resp.get("headers", {}).items():
            self.send_header(k, v.replace("{MOCK}", origin))
        self.end_headers()
        try:
            if chunks > 0:
                step = max(1, -(-len(data) // chunks))
                for i in range(0, len(data), step):
                    piece = data[i:i + step]
                    self.wfile.write(b"%x\r\n" % len(piece) + piece + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = handle_any


class MockServer(ThreadingHTTPServer):
    """One mock instance: MockServer(config_dict, log_path, port=0).

    port 0 lets the kernel pick a free port (see .port / .origin), so
    concurrent runs never collide.  A busy fixed port raises OSError."""
    daemon_threads = True
    block_on_close = False  # stop() must not wait for delayed responses

    def __init__(self, cfg: dict, log_path, port: int = 0):
        self.cfg = cfg
        self.cursor = {}
        self.count = 0
        self.pending = 0
        self.lock = threading.Lock()
        self.logf = open(log_path, "w")
        try:
            super().__init__(("127.0.0.1", port), Handler)
        except OSError:
            self.logf.close()
            raise
        self.port = self.server_address[1]
        self.origin = "http://127.0.0.1:%d" % self.port
        self.thread = None

    def handle_error(self, request, client_address):
        pass  # clients that went away / malformed requests

    def track(self, delta):
        with self.lock:
            self.pending += delta

    def record(self, rec, key_exact, key_any):
        routes = self.cfg.get("routes", {})
        with self.lock:
            if self.logf.closed:  # straggler after stop()
                return {"drop": True}
            self.count += 1
            rec["seq"] = self.count
            key = key_exact if key_exact in routes else key_any
            lst = routes.get(key)
            if lst:
                i = self.cursor.get(key, 0)
                resp = lst[min(i, len(lst) - 1)]
                self.cursor[key] = i + 1
            else:
                resp = self.cfg.get("default", {"json": {"response_code": 1, "verbose_msg": "mock default"}})
            self.logf.write(json.dumps(rec, sort_keys=True) + "\n")
            self.logf.flush()
        return resp

    def start(self):
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()
        return self

    def stop(self, grace=2.0):
        """Stop serving; first give requests that already reached the mock
        (but are not logged yet) up to `grace` seconds to be logged."""
        t_end = time.time() + grace
        while time.time() < t_end:
            with self.lock:
                if self.pending <= 0:
                    break
            time.sleep(0.02)
        self.shutdown()
        self.server_close()
        with self.lock:
            self.logf.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--config", required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    with open(a.config) as f:
        cfg = json.load(f)
    srv = MockServer(cfg, a.log, a.port)
    print(srv.port, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
