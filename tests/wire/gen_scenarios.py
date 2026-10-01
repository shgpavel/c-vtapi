#!/usr/bin/env python3
"""The wire-level scenario table: the source of truth of this suite.

Each add(...) below is one scenario: a CLI tool (or the `vtprobe` library
driver) with its argv / stdin / input files, the mock's canned responses,
and the MODEL -- the exact list of HTTP requests a correct implementation
sends (method, path, decoded query pairs, content type, form / multipart
part names, filenames and content hashes) plus the files it creates in its
working directory.  `note` documents why a model looks the way it does;
"Dn" tags refer to the behaviour fixes of the 1.0 redesign (D1 file/scan
upload body, D2 scanMemBuf buffer, D3 big-file upload body, D4 URL
escaping, D5 url report flags, D7 cancel reset, D8 robustness, D9 search
offsets, D11 VT_API_BASE_URL).

    python3 gen_scenarios.py --out DIR      (run.py does this itself)

writes DIR/<id>/{scenario.json, config.json, expect.json, inputs/}.
scenario.json keys are documented in run.py, config.json in mockvt.py;
expect.json is {"requests": [...], "files": {rel: {len, sha256}}, "note"}.
"""
import argparse
import base64
import datetime
import json
import shutil
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # keep the source tree clean
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_util import blob, blob_of_gen, gen_bytes  # noqa: E402

K = "TESTKEY"
B = "/vtapi/v2/"
MiB = 1 << 20

SC = {}


# ---------------------------------------------------------------- helpers
def add(sid, tool, argv, routes=None, expect=(), note=None, files=None,
        inputs=None, timeout=20, default=None, **extra):
    """files: {rel path: blob} of every file the tool must create in its
    cwd (default: none).  extra: further scenario.json keys (see run.py)."""
    assert sid not in SC, sid
    SC[sid] = dict(tool=tool, argv=list(argv), routes=routes or {},
                   expect=list(expect), note=note, files=files or {},
                   inputs=inputs or {}, timeout=timeout, default=default,
                   extra=extra)


def R(method, path):
    return f"{method} {path if path.startswith('/') else B + path}"


def J(obj, status=200, **kw):
    d = {"status": status, "json": obj}
    d.update(kw)
    return d


def T(body, status=200, **kw):
    d = {"status": status, "body": body}
    d.update(kw)
    return d


def BIN(data: bytes, status=200, **kw):
    d = {"status": status, "body_b64": base64.b64encode(data).decode()}
    d.update(kw)
    return d


DROP = {"drop": True}


def GET(path, *q):
    return {"method": "GET", "path": path if path.startswith("/") else B + path,
            "query": [list(x) for x in q]}


def MP(path, *parts):
    return {"method": "POST", "path": path if path.startswith("/") else B + path,
            "query": [], "content_type": "multipart/form-data",
            "multipart": list(parts)}


def _b(v):
    return v.encode() if isinstance(v, str) else v


def P(name, value):
    return {"name": name, "data": blob(_b(value))}


def F(name, filename, data):
    p = {"filename": filename, "data": data if isinstance(data, dict) else blob(_b(data))}
    if name is not None:
        p["name"] = name
    return p


# common data
SAMPLE = gen_bytes(5000, "sample")
HELLO = b"hello world\n"
H32 = "44d88612fea8a8f36de82e1278abb02f"
OK = {"response_code": 1, "verbose_msg": "ok"}
STDIN = "STDIN-PAYLOAD\n"
IP = "ip-address/report"
DOM = "domain/report"


def kq(*extra):
    return (("apikey", K),) + extra


# ================================================================== scan
D1 = "D1: file/scan part 'file' must carry the real file bytes (filename=basename), part 'filename' the path as given"
D2 = "D2: scanMemBuf part 'file' must carry the caller's memory buffer with the caller's filename (old code uploads the disk file named 'filename', unnamed part)"
D3 = "D3: scanBigFile upload POST must carry the real file bytes (filename=basename) plus part 'filename' = path, no apikey"
D4 = "D4: query-string values must be URL-escaped (old code injects/truncates/rejects raw values)"


def scan_file_req(path, data, notify=None, key=K):
    parts = [F("file", Path(path).name, data), P("filename", path)]
    if notify:
        parts.append(P("notify_url", notify))
    parts.append(P("apikey", key))
    return MP("file/scan", *parts)


def rep(res, key=K):
    return MP("file/report", P("resource", res), P("apikey", key))


add("scan_usage", "scan", [])
add("scan_help", "scan", ["--help"])
add("scan_help_midway", "scan",
    ["--apikey", K, "--report", "R1", "--help=x", "--report", "R2", "stray"],
    {R("POST", "file/report"): [J({"response_code": 1, "verbose_msg": "ok", "resource": "R1"})]},
    [rep("R1")])
for op, args in [("filescan", ["--filescan", "inputs/hello.txt"]),
                 ("scaninput", ["--scaninput"]),
                 ("rescan", ["--rescan", "H"]),
                 ("report", ["--report", "H"]),
                 ("clusters", ["--clusters", "2024-01-02"]),
                 ("download", ["--out", "o.bin", "--download", "H"])]:
    add(f"scan_need_apikey_{op}", "scan", args + ["--apikey", K],
        inputs={"hello.txt": HELLO}, stdin="X")
add("scan_need_out", "scan", ["--apikey", K, "--download", "H", "--out", "o.bin"])

add("scan_filescan_ok", "scan", ["--apikey", K, "--filescan", "inputs/sample.bin"],
    {R("POST", "file/scan"): [J({"response_code": 1, "verbose_msg": "Scan request successfully queued",
                                 "resource": "abc", "scan_id": "abc-123"})]},
    [scan_file_req("inputs/sample.bin", SAMPLE)], note=D1, inputs={"sample.bin": SAMPLE})
add("scan_filescan_missing_then_ok", "scan",
    ["--apikey", K, "--filescan", "inputs/missing.bin", "--filescan", "inputs/hello.txt"],
    {R("POST", "file/scan"): [J(OK)]},
    [scan_file_req("inputs/hello.txt", HELLO)], note=D1, inputs={"hello.txt": HELLO})
add("scan_filescan_errors", "scan",
    ["--apikey", K] + ["--filescan", "inputs/hello.txt"] * 5,
    {R("POST", "file/scan"): [J({"response_code": 0, "verbose_msg": "Internal error"}, 500),
                              T("Forbidden", 403), T("", 204), T("not json"), T("")]},
    [scan_file_req("inputs/hello.txt", HELLO)] * 5, note=D1, inputs={"hello.txt": HELLO})
add("scan_filescan_boundary_small", "scan", ["--apikey", K, "--filescan", "inputs/almost.bin"],
    {R("POST", "file/scan"): [J({"response_code": 1, "verbose_msg": "small"})]},
    [scan_file_req("inputs/almost.bin", blob_of_gen(64 * MiB - 1, "almost"))], note=D1,
    gen=[{"path": "inputs/almost.bin", "size": 64 * MiB - 1, "seed": "almost"}], timeout=120)

BIG = blob_of_gen(64 * MiB, "big")
BIGGEN = [{"path": "inputs/big.bin", "size": 64 * MiB, "seed": "big"}]


def upload(path, fname, blob):
    return MP(path, F("file", Path(fname).name, blob), P("filename", fname))


add("scan_bigfile_ok", "scan", ["--apikey", K, "--filescan", "inputs/big.bin"],
    {R("GET", "file/scan/upload_url"): [J({"upload_url": "{MOCK}/_ah/upload/TOKEN123/"})],
     R("POST", "/_ah/upload/TOKEN123/"): [J({"response_code": 1, "verbose_msg": "big queued", "scan_id": "big-1"})]},
    [GET("file/scan/upload_url", ("apikey", K)), upload("/_ah/upload/TOKEN123/", "inputs/big.bin", BIG)],
    note=D3, gen=BIGGEN, timeout=120)
add("scan_bigfile_no_upload_url", "scan", ["--apikey", K, "--filescan", "inputs/big.bin"],
    {R("GET", "file/scan/upload_url"): [J({"response_code": 0, "verbose_msg": "server says no url"}, 500)]},
    [GET("file/scan/upload_url", ("apikey", K))], gen=BIGGEN, timeout=120)
add("scan_bigfile_upload_url_dropped", "scan", ["--apikey", K, "--filescan", "inputs/big.bin"],
    {R("GET", "file/scan/upload_url"): [DROP]},
    [GET("file/scan/upload_url", ("apikey", K))], gen=BIGGEN, timeout=120)
add("scan_bigfile_upload_fail", "scan", ["--apikey", K, "--filescan", "inputs/big.bin"],
    {R("GET", "file/scan/upload_url"): [J({"upload_url": "{MOCK}/_ah/upload/T2/"})],
     R("POST", "/_ah/upload/T2/"): [J({"err": 1}, 413)]},
    [GET("file/scan/upload_url", ("apikey", K)), upload("/_ah/upload/T2/", "inputs/big.bin", BIG)],
    note=D3, gen=BIGGEN, timeout=120)
add("scan_bigfile_redirects", "scan", ["--apikey", K, "--filescan", "inputs/big.bin"],
    {R("GET", "file/scan/upload_url"): [T("", 302, headers={"Location": "/vtapi/v2/file/scan/upload_url2"})],
     R("GET", "file/scan/upload_url2"): [J({"upload_url": "{MOCK}/_ah/upload/T/"})],
     R("POST", "/_ah/upload/T/"): [T("", 302, headers={"Location": "/_ah/final"})],
     R("GET", "/_ah/final"): [J({"response_code": 1, "verbose_msg": "final"})]},
    [GET("file/scan/upload_url", ("apikey", K)), GET("file/scan/upload_url2"),
     upload("/_ah/upload/T/", "inputs/big.bin", BIG), GET("/_ah/final")],
    note=D3, gen=BIGGEN, timeout=120)

# --scaninput (VtFile_scanMemBuf)
add("scan_scaninput_default", "scan", ["--apikey", K, "--scaninput"],
    {R("POST", "file/scan"): [J(OK)]},
    [MP("file/scan", F("file", "filename", STDIN), P("apikey", K))], note=D2,
    inputs={"filename": b"DEFAULT-NAME-FILE"}, inputs_at_cwd=True, stdin=STDIN)
add("scan_scaninput_named", "scan", ["--apikey", K, "--scaninput=upload.txt"],
    {R("POST", "file/scan"): [J(OK)]},
    [MP("file/scan", F("file", "upload.txt", STDIN), P("apikey", K))], note=D2,
    inputs={"upload.txt": b"DISK-CONTENT-OF-upload.txt\n"}, inputs_at_cwd=True, stdin=STDIN)
add("scan_scaninput_missing_disk_file", "scan", ["--apikey", K, "--scaninput"],
    {R("POST", "file/scan"): [J(OK)]},
    [MP("file/scan", F("file", "filename", STDIN), P("apikey", K))],
    note=D2 + " (no disk file of that name exists)",
    stdin=STDIN)
add("scan_scaninput_separate_arg", "scan", ["--apikey", K, "--scaninput", "ondisk.txt"],
    {R("POST", "file/scan"): [J(OK)]},
    [MP("file/scan", F("file", "filename", STDIN), P("apikey", K))], note=D2,
    inputs={"filename": b"DEFAULT-NAME-FILE", "ondisk.txt": b"ONDISK\n"}, inputs_at_cwd=True, stdin=STDIN)
add("scan_scaninput_empty_stdin", "scan", ["--apikey", K, "--scaninput"])
add("scan_scaninput_32mib", "scan", ["--apikey", K, "--scaninput"],
    inputs={"filename": b"DEFAULT"}, inputs_at_cwd=True,
    stdin_gen={"size": 32 * MiB, "seed": "mem"}, timeout=60)
add("scan_scaninput_32mib_minus1", "scan", ["--apikey", K, "--scaninput"],
    {R("POST", "file/scan"): [J(OK)]},
    [MP("file/scan", F("file", "filename", blob_of_gen(32 * MiB - 1, "mem")), P("apikey", K))],
    note=D2, inputs={"filename": b"DEFAULT"}, inputs_at_cwd=True,
    stdin_gen={"size": 32 * MiB - 1, "seed": "mem"}, timeout=60)

# rescan / report
add("scan_rescan_ok", "scan", ["--apikey", K, "--rescan", H32],
    {R("POST", "file/rescan"): [J({"response_code": 1, "verbose_msg": "Scan request successfully queued",
                                   "resource": H32, "scan_id": "x"})]},
    [MP("file/rescan", P("resource", H32), P("apikey", K))])
add("scan_rescan_errors", "scan", ["--apikey", K, "--rescan", "H1", "--rescan", "H2", "--rescan", "H3"],
    {R("POST", "file/rescan"): [J({"response_code": 0, "verbose_msg": "boom"}, 500), T("not json"),
                                J({"response_code": 0, "verbose_msg": "not found"})]},
    [MP("file/rescan", P("resource", h), P("apikey", K)) for h in ("H1", "H2", "H3")])
add("scan_report_ok", "scan", ["--apikey", K, "--report", H32],
    {R("POST", "file/report"): [J({"response_code": 1, "verbose_msg": "Scan finished, information embedded",
                                   "resource": H32, "positives": 3, "total": 60,
                                   "scans": {"AV1": {"detected": True, "result": "EICAR"}}})]},
    [rep(H32)])
add("scan_report_edge_sequence", "scan", ["--apikey", K] + sum([["--report", f"r{i}"] for i in range(1, 10)], []),
    {R("POST", "file/report"): [T("", 204), T("Forbidden", 403), T("not json"), T("[1,2]"),
                                J({"resource": "x"}), J({"response_code": "1", "verbose_msg": "L" * 300}),
                                J({"response_code": 0, "verbose_msg": ""}), T(""),
                                J({"response_code": -2, "verbose_msg": "short"})]},
    [rep(f"r{i}") for i in range(1, 10)])
add("scan_report_response_code_0", "scan", ["--apikey", K, "--report", "R0"],
    {R("POST", "file/report"): [J({"response_code": 0, "verbose_msg": "The requested resource is not among the finished, queued or pending scans"})]},
    [rep("R0")])
add("scan_report_verbose_msg_null", "scan", ["--apikey", K, "--report", "r1"],
    {R("POST", "file/report"): [J({"response_code": 1, "verbose_msg": None})]},
    [rep("r1")], note="D8: old code segfaults on JSON null verbose_msg (strdup(NULL))")
add("scan_report_chunked", "scan", ["--apikey", K, "--report", "RC"],
    {R("POST", "file/report"): [J({"response_code": 1, "verbose_msg": "chunked body", "pad": "x" * 3000}, chunks=7)]},
    [rep("RC")])

# clusters
CL = {"response_code": 1, "verbose_msg": "ok", "offset": "OFFX", "size_top200": 1, "num_clusters": 2,
      "clusters": [{"id": "c1", "label": "l1", "size": 3, "avg_positives": 1}, "notobj",
                   {"id": "c2", "label": "l2", "size": 1, "avg_positives": 0}]}
add("scan_clusters_ok", "scan", ["--apikey", K, "--cluster", "2024-01-02", "--clusters=2024-01-03"],
    {R("GET", "file/clusters"): [J(CL)]},
    [GET("file/clusters", *kq(("date", "2024-01-02"))), GET("file/clusters", *kq(("date", "2024-01-03")))])
add("scan_clusters_edge", "scan", ["--apikey", K] + sum([["--clusters", f"d{i}"] for i in range(1, 6)], []),
    {R("GET", "file/clusters"): [J({"response_code": 1}), T("", 404), T("not json"), J({"clusters": "notarray"}),
                                 J({"response_code": 0, "verbose_msg": "err"}, 500)]},
    [GET("file/clusters", *kq(("date", f"d{i}"))) for i in range(1, 6)])
add("scan_clusters_empty_date", "scan", ["--apikey", K, "--clusters="])
add("scan_clusters_drop", "scan", ["--apikey", K, "--clusters", "2024-01-02", "--clusters", "2024-01-03"],
    {R("GET", "file/clusters"): [DROP, J(CL)]},
    [GET("file/clusters", *kq(("date", "2024-01-02"))), GET("file/clusters", *kq(("date", "2024-01-03")))])

# download
DL = gen_bytes(40000, "dl")
add("scan_download_ok", "scan", ["--apikey", K, "--out", "o.bin", "--download", "H1"],
    {R("GET", "file/download"): [BIN(DL, chunks=5)]},
    [GET("file/download", *kq(("hash", "H1")))], files={"o.bin": blob(DL)})
add("scan_download_redirect_and_404", "scan",
    ["--apikey", K, "--out", "out.bin", "--download", "h1", "--out", "out2.bin", "--download", "h2"],
    {R("GET", "file/download"): [T("", 302, headers={"Location": "{MOCK}/storage/blob1"}), T('{"error":"nf"}', 404)],
     R("GET", "/storage/blob1"): [T("REDIRECTED-CONTENT")]},
    [GET("file/download", *kq(("hash", "h1"))), GET("/storage/blob1"), GET("file/download", *kq(("hash", "h2")))],
    files={"out.bin": blob(b"REDIRECTED-CONTENT"), "out2.bin": blob(b'{"error":"nf"}')},
    note="redirects are followed; a 404 body is still written to --out")
add("scan_download_local_errors", "scan",
    ["--apikey", K, "--out", "/nonexistent/dir/x", "--download", "h1", "--out", "empty.bin", "--download="],
    files={"empty.bin": blob(b"")},
    note="an unopenable --out sends nothing; --download= (empty hash) creates the --out file, then fails")
add("scan_download_drop", "scan", ["--apikey", K, "--out", "d.bin", "--download", "h1", "--out", "e.bin", "--download", "h2"],
    {R("GET", "file/download"): [DROP, T("SECOND")]},
    [GET("file/download", *kq(("hash", "h1"))), GET("file/download", *kq(("hash", "h2")))],
    files={"d.bin": blob(b""), "e.bin": blob(b"SECOND")})

# escaping (D4)
add("scan_escape_clusters", "scan", ["--apikey", K, "--clusters", "2024-01-02&z=1"],
    {R("GET", "file/clusters"): [J({"response_code": 1, "clusters": []})]},
    [GET("file/clusters", *kq(("date", "2024-01-02&z=1")))], note=D4)
add("scan_escape_clusters_space", "scan", ["--apikey", K, "--clusters", "2024 01 02"],
    {R("GET", "file/clusters"): [J({"response_code": 1, "clusters": []})]},
    [GET("file/clusters", *kq(("date", "2024 01 02")))],
    note=D4 + " (old code: curl rejects the space, no request)")
add("scan_escape_download", "scan",
    ["--apikey", K, "--out", "o.bin", "--download", "abc&z=1", "--out", "o2.bin", "--download", "a b#c"],
    {R("GET", "file/download"): [T("DATA")]},
    [GET("file/download", *kq(("hash", "abc&z=1"))), GET("file/download", *kq(("hash", "a b#c")))],
    note=D4 + " (old code: '&' injects a param, space makes curl reject the URL and o2.bin stays empty)",
    files={"o.bin": blob(b"DATA"), "o2.bin": blob(b"DATA")})
add("scan_escape_apikey", "scan",
    ["--apikey", "K&x=1", "--clusters", "2024-01-02", "--out", "o.bin", "--download", "H", "--report", "R"],
    {R("GET", "file/clusters"): [J({"response_code": 1, "clusters": []})],
     R("GET", "file/download"): [T("D")], R("POST", "file/report"): [J(OK)]},
    [GET("file/clusters", ("apikey", "K&x=1"), ("date", "2024-01-02")),
     GET("file/download", ("apikey", "K&x=1"), ("hash", "H")), rep("R", key="K&x=1")],
    note=D4 + " (multipart apikey stays verbatim)", files={"o.bin": blob(b"D")})

# getopt surface
add("scan_verbose", "scan", ["--verbose", "--verbose=3", "-v", "3"])
add("scan_getopt_errors", "scan", ["-a", K, "--re", "x", "-r", "y", "-i", "z", "--bogus", "--filescan"])
add("scan_abbreviations", "scan",
    ["-a", K, "-f", "inputs/hello.txt", "-rep", "R1", "-res", "R2", "-c", "2024-01-01", "-o", "o.bin", "-d", "H", "-s"],
    {R("POST", "file/scan"): [J({"response_code": 1, "verbose_msg": "m"})],
     R("POST", "file/report"): [J({"response_code": 1, "verbose_msg": "m"})],
     R("POST", "file/rescan"): [J({"response_code": 1, "verbose_msg": "m"})],
     R("GET", "file/clusters"): [J({"response_code": 1})],
     R("GET", "file/download"): [T("D")]},
    [scan_file_req("inputs/hello.txt", HELLO), rep("R1"), MP("file/rescan", P("resource", "R2"), P("apikey", K)),
     GET("file/clusters", *kq(("date", "2024-01-01"))), GET("file/download", *kq(("hash", "H")))],
    note=D1, inputs={"hello.txt": HELLO}, files={"o.bin": blob(b"D")})
add("scan_nonoptions_permute", "scan", ["--apikey", K, "stray1", "--report", "R", "--", "--notanoption"],
    {R("POST", "file/report"): [J(OK)]}, [rep("R")])
add("scan_posixly_correct", "scan", ["--apikey", K, "stray", "--report", "R"], env={"POSIXLY_CORRECT": "1"})
add("scan_apikey_twice", "scan", ["--apikey", "A", "--apikey", "B", "--report", "R"],
    {R("POST", "file/report"): [J(OK)]}, [rep("R", key="B")])
add("scan_apikey_empty", "scan", ["--apikey=", "--report", "R"],
    {R("POST", "file/report"): [J(OK)]}, [rep("R", key="")])
add("scan_conn_refused", "scan",
    ["--apikey", K, "--report", "R", "--filescan", "inputs/hello.txt", "--clusters", "2024-01-01",
     "--rescan", "R", "--out", "o.bin", "--download", "H", "--scaninput=hello.txt"],
    inputs={"hello.txt": HELLO}, no_mock=True, stdin="abc", files={"o.bin": blob(b"")},
    note="connection refused everywhere: nothing is recorded, the --out file is still created")
add("scan_vt_debug", "scan", ["--apikey", K, "--report", "R"],
    {R("POST", "file/report"): [J(OK)]}, [rep("R")], env={"VT_DEBUG": "1"})

# signals / cancellation through the progress callback
add("scan_sigterm_filescan", "scan", ["--apikey", K, "--filescan", "inputs/hello.txt"],
    {R("POST", "file/scan"): [J(OK, delay=3)]},
    [scan_file_req("inputs/hello.txt", HELLO)], note=D1, inputs={"hello.txt": HELLO},
    signal={"name": "SIGTERM", "after_requests": 1, "delay": 0.3})
add("scan_sighup_download", "scan", ["--apikey", K, "--out", "dl.bin", "--download", "h", "--download", "h2"],
    {R("GET", "file/download"): [T("DATA", delay=3)]},
    [GET("file/download", *kq(("hash", "h")))], files={"dl.bin": blob(b"")},
    signal={"name": "SIGHUP", "after_requests": 1, "delay": 0.3},
    note="SIGHUP cancels the running download and every later operation")
add("scan_sigterm_then_more_ops", "scan",
    ["--apikey", K, "--report", "R1", "--clusters", "2024-01-01", "--report", "R2"],
    {R("POST", "file/report"): [J(OK, delay=3), J(OK)], R("GET", "file/clusters"): [J({"clusters": []})]},
    [rep("R1")], signal={"name": "SIGTERM", "after_requests": 1, "delay": 0.3})

# ================================================================= search
D9 = "D9: search must send 'offset' only when the caller set one for this call; a stale offset (response without a string offset) must not be re-sent"


def srch(q, offset=None, key=K):
    parts = [P("query", q), P("apikey", key)]
    if offset is not None:
        parts.append(P("offset", offset))
    return MP("file/search", *parts)


add("search_usage", "search", [])
add("search_help", "search", ["--apikey", K, "--query", "q", "--help"])
add("search_basic", "search", ["--apikey", K, "--query", "type:peexe positives:5+"],
    {R("POST", "file/search"): [J({"response_code": 1, "verbose_msg": "ok", "offset": "PAGE2", "hashes": ["h1", "h2"]})]},
    [srch("type:peexe positives:5+")])
add("search_pagination", "search",
    ["--query", "type:peexe", "--apikey", K, "--offset", "START", "--repeat", "8"],
    {R("POST", "file/search"): [
        J({"response_code": 1, "verbose_msg": "ok", "offset": "PAGE2", "hashes": ["h1", "h2"]}),
        J({"response_code": 1, "verbose_msg": "ok", "offset": "PAGE3", "hashes": ["h3", 5, "h4"]}),
        J({"response_code": 1, "verbose_msg": "ok", "offset": "PAGE4", "hashes": ["h5"]}),
        J({"response_code": 0, "verbose_msg": "no hashes key", "offset": "PAGE5"}),
        J({"response_code": 1, "verbose_msg": "ok", "offset": "PAGE6", "hashes": []}),
        T("", 204)]},
    [srch("type:peexe", o) for o in ("START", "PAGE2", "PAGE3", "PAGE4", "PAGE5", "PAGE6")])
add("search_offset_stale", "search", ["--apikey", K, "--query", "q", "--offset", "START", "--repeat", "4"],
    {R("POST", "file/search"): [J({"offset": "P2", "hashes": ["a"]}), J({"hashes": ["b"]}),
                                J({"offset": 12345, "hashes": ["c"]}), J({"hashes": []})]},
    [srch("q", "START"), srch("q", "P2"), srch("q"), srch("q")], note=D9)
add("search_offset_empty_string", "search", ["--apikey", K, "--query", "q", "--repeat", "2"],
    {R("POST", "file/search"): [J({"offset": "", "hashes": ["a"]}), J({"hashes": []})]},
    [srch("q"), srch("q")],
    note="D9: a response offset of \"\" means there is no next page; the next request carries no offset part")
add("search_no_query", "search", ["--apikey", K])
add("search_no_apikey", "search", ["--query", "q1"],
    {R("POST", "file/search"): [J({"hashes": ["h1"]})]}, [srch("q1", key="")])
add("search_repeat_zero", "search", ["--apikey", K, "--query", "q", "--repeat=0", "extra1"])
add("search_last_wins", "search",
    ["--apikey", "A", "--apikey", "B", "--query", "q1", "--query", "q2", "--offset", "O1", "--offset", "O2"],
    {R("POST", "file/search"): [J({"hashes": []})]}, [srch("q2", "O2", key="B")])
add("search_getopt_mix", "search", ["-a", K, "-q=abc", "--verbose", "--verbose=3", "--bogus", "-rep", "1", "-o"],
    {R("POST", "file/search"): [J({"offset": "P2", "hashes": ["h1", "h2"]})]}, [srch("abc")])
add("search_invalid_json", "search", ["--apikey", K, "--query", "q", "--repeat", "3"],
    {R("POST", "file/search"): [T("not json")]}, [srch("q")])
add("search_http_500", "search", ["--apikey", K, "--query", "q", "--repeat", "2"],
    {R("POST", "file/search"): [J({"response_code": 0, "verbose_msg": "err"}, 500)]}, [srch("q")])
add("search_drop", "search", ["--apikey", K, "--query", "q", "--repeat", "2"],
    {R("POST", "file/search"): [DROP]}, [srch("q")])
add("search_conn_refused", "search", ["--apikey", K, "--query", "q"], no_mock=True)
add("search_special_chars", "search", ["--apikey", 'k"ü', "--query", 'type:"peexe" & ü'],
    {R("POST", "file/search"): [J({"hashes": ["x"]})]}, [srch('type:"peexe" & ü', key='k"ü')])
add("search_verbose_msg_null", "search", ["--apikey", K, "--query", "q"],
    {R("POST", "file/search"): [J({"verbose_msg": None, "hashes": ["a"]})]}, [srch("q")],
    note="D8: old code segfaults on JSON null verbose_msg")

# ===================================================================== ip
add("ip_usage", "ip", [])
add("ip_report_ok", "ip", ["--apikey", K, "--report", "1.2.3.4"],
    {R("GET", IP): [J({"response_code": 1, "verbose_msg": "IP address in dataset", "asn": "123",
                       "resolutions": [{"hostname": "a.b", "last_resolved": "2014-01-01 00:00:00"}]})]},
    [GET(IP, *kq(("ip", "1.2.3.4")))])
add("ip_no_apikey", "ip", ["--verbose", "--report", "1.2.3.4"])
add("ip_multi_options", "ip",
    ["-apikey", "K1", "--apikey=K2", "--rep=1.1.1.1", "-report", "2.2.2.2", "extra1", "--verbose=3", "-v",
     "--help=x", "--bogus", "--report"],
    {R("GET", IP): [J({"response_code": 1}), J({"response_code": 0, "verbose_msg": "second"}, 500)]},
    [GET(IP, ("apikey", "K2"), ("ip", "1.1.1.1")), GET(IP, ("apikey", "K2"), ("ip", "2.2.2.2"))])
add("ip_nonjson", "ip", ["--apikey", K, "--report", "1.2.3.4"], {R("GET", IP): [T("not json")]},
    [GET(IP, *kq(("ip", "1.2.3.4")))])
add("ip_empty_204", "ip", ["--apikey", K, "--report", "1.2.3.4"], {R("GET", IP): [T("", 204)]},
    [GET(IP, *kq(("ip", "1.2.3.4")))])
add("ip_response_code_0", "ip", ["--apikey", K, "--report", "10.0.0.1"],
    {R("GET", IP): [J({"response_code": 0, "verbose_msg": "IP address not in dataset"})]},
    [GET(IP, *kq(("ip", "10.0.0.1")))])
add("ip_chunked", "ip", ["--apikey", K, "--report", "1.2.3.4"],
    {R("GET", IP): [J({"response_code": 1, "verbose_msg": "chunky", "detected_urls": ["u%d" % i for i in range(200)]}, chunks=9)]},
    [GET(IP, *kq(("ip", "1.2.3.4")))])
add("ip_escape_amp", "ip", ["--apikey", K, "--report", "1.2.3.4&x=y"], {R("GET", IP): [J({"response_code": 0})]},
    [GET(IP, *kq(("ip", "1.2.3.4&x=y")))], note=D4)
add("ip_escape_hash_pct", "ip", ["--apikey", K, "--report", "a#frag", "--report", "b%41+c"],
    {R("GET", IP): [J({"response_code": 0})]},
    [GET(IP, *kq(("ip", "a#frag"))), GET(IP, *kq(("ip", "b%41+c")))], note=D4)
add("ip_escape_space_stale", "ip", ["--apikey", K, "--report", "1.1.1.1", "--report", "x y"],
    {R("GET", IP): [J({"response_code": 1, "verbose_msg": "first"}), J({"response_code": 1, "verbose_msg": "second"})]},
    [GET(IP, *kq(("ip", "1.1.1.1"))), GET(IP, *kq(("ip", "x y")))],
    note=D4 + " + D8 (old code: curl rejects the space and the stale first response is printed again)")
add("ip_long", "ip", ["--apikey", K, "--report", "1" * 600], {R("GET", IP): [J({})]},
    [GET(IP, *kq(("ip", "1" * 600)))], note="D8: long inputs must not be truncated (old code snprintf into char[512] cuts the URL)")
add("ip_drop_crash", "ip", ["--apikey", K, "--report", "1.2.3.4"], {R("GET", IP): [DROP]},
    [GET(IP, *kq(("ip", "1.2.3.4")))],
    note="D8: old code segfaults (NULL response after a transfer failure)")
add("ip_verbose_msg_null", "ip", ["--apikey", K, "--report", "1.2.3.4"],
    {R("GET", IP): [J({"response_code": 1, "verbose_msg": None})]}, [GET(IP, *kq(("ip", "1.2.3.4")))],
    note="D8: old code segfaults on JSON null verbose_msg")
add("ip_conn_refused", "ip", ["--apikey", K, "--report", "1.2.3.4"], no_mock=True,
    note="D8: old code segfaults on connection failure")
add("ip_drop_stale", "ip", ["--apikey", K, "--report", "1.1.1.1", "--report", "2.2.2.2"],
    {R("GET", IP): [J({"response_code": 1, "verbose_msg": "first"}), DROP]},
    [GET(IP, *kq(("ip", "1.1.1.1"))), GET(IP, *kq(("ip", "2.2.2.2")))])
add("ip_vt_debug", "ip", ["--apikey", K, "--report", "1.2.3.4"], {R("GET", IP): [J({"a": 1})]},
    [GET(IP, *kq(("ip", "1.2.3.4")))], env={"VT_DEBUG": "1"})

# ================================================================= domain
add("dom_usage", "domain_report", [])
add("dom_report_ok", "domain_report", ["--apikey", K, "--report", "example.com"],
    {R("GET", DOM): [T('{"e":{},"a":[],"f":1.5,"g":1e300,"h":2.9,"s":"é/\\u0001\\"","t":true,"n":null,"i":-3,'
                       '"z":{"b":2,"a":1},"response_code":1,"verbose_msg":"Domain found in dataset"}')]},
    [GET(DOM, *kq(("domain", "example.com")))])
add("dom_no_apikey", "domain_report", ["--report", "example.com"])
add("dom_multi_help_nonopt", "domain_report",
    ["--apikey", K, "--report", "a.com", "--help", "--verbose=2", "--report", "b.com", "stray"],
    {R("GET", DOM): [J({"response_code": 1, "verbose_msg": "Domain found"}), J({"response_code": -1}, 403)]},
    [GET(DOM, *kq(("domain", "a.com"))), GET(DOM, *kq(("domain", "b.com")))])
add("dom_nonjson", "domain_report", ["--apikey", K, "--report", "example.com"], {R("GET", DOM): [T("oops")]},
    [GET(DOM, *kq(("domain", "example.com")))])
add("dom_response_code_0", "domain_report", ["--apikey", K, "--report", "unknown.example"],
    {R("GET", DOM): [J({"response_code": 0, "verbose_msg": "Domain not found"})]},
    [GET(DOM, *kq(("domain", "unknown.example")))])
add("dom_drop", "domain_report", ["--apikey", K, "--report", "example.com", "--report", "example.org"],
    {R("GET", DOM): [DROP, J(OK)]},
    [GET(DOM, *kq(("domain", "example.com"))), GET(DOM, *kq(("domain", "example.org")))])
add("dom_escape_amp", "domain_report", ["--apikey", K, "--report", "a.com&x=y"],
    {R("GET", DOM): [J({"response_code": 0})]}, [GET(DOM, *kq(("domain", "a.com&x=y")))], note=D4)
add("dom_escape_space", "domain_report", ["--apikey", K, "--report", "bad dom"],
    {R("GET", DOM): [J({"response_code": 0})]}, [GET(DOM, *kq(("domain", "bad dom")))],
    note=D4 + " (old code: curl rejects the space, no request)")
add("dom_long", "domain_report", ["--apikey", K, "--report", "d" * 600 + ".com"], {R("GET", DOM): [J({})]},
    [GET(DOM, *kq(("domain", "d" * 600 + ".com")))], note="D8: long inputs must not be truncated")
add("dom_verbose_msg_null", "domain_report", ["--apikey", K, "--report", "example.com"],
    {R("GET", DOM): [J({"response_code": 1, "verbose_msg": None})]}, [GET(DOM, *kq(("domain", "example.com")))],
    note="D8: old code segfaults on JSON null verbose_msg")

# ==================================================================== url
D5 = "D5: url --all-info must send all_info=1 and --report-scan must send scan=1 (old code swaps them)"


def urep(res, *flags, key=K):
    return MP("url/report", P("resource", res), P("apikey", key), *[P(f, "1") for f in flags])


def uscan(u, key=K):
    return MP("url/scan", P("url", u), P("apikey", key))


add("url_usage", "url", [])
add("url_scan_ok", "url", ["--apikey", K, "--scan", "http://ex.com/a b?x=1&y=2"],
    {R("POST", "url/scan"): [J({"response_code": 1, "scan_id": "abc-123", "verbose_msg": "Scan request successfully queued"})]},
    [uscan("http://ex.com/a b?x=1&y=2")])
add("url_report_plain", "url", ["--apikey", K, "--report", "http://ex.com"],
    {R("POST", "url/report"): [J({"response_code": 1, "positives": 0})]}, [urep("http://ex.com")])
add("url_report_allinfo", "url", ["--apikey", K, "--all-info", "--report", "http://ex.com"],
    {R("POST", "url/report"): [J({"response_code": 1})]}, [urep("http://ex.com", "all_info")], note=D5)
add("url_report_reportscan", "url", ["--apikey", K, "--report-scan", "--report", "http://ex.com"],
    {R("POST", "url/report"): [J({"response_code": 1})]}, [urep("http://ex.com", "scan")], note=D5)
add("url_mixed_order", "url",
    ["--apikey", K, "--report", "http://a.com", "--all-info", "--report-scan", "--report", "http://b.com",
     "--scan", "http://c.com", "--verbose=1"],
    {R("POST", "url/report"): [J({"response_code": 1})], R("POST", "url/scan"): [T("[1,2]")]},
    [urep("http://a.com"), urep("http://b.com", "scan", "all_info"), uscan("http://c.com")])
add("url_no_apikey_scan", "url", ["--scan", "http://x"])
add("url_no_apikey_report", "url", ["--report", "http://x"])
add("url_help_exits", "url", ["--apikey", K, "--help", "--report", "http://x"])
add("url_ambiguous", "url", ["-a", K, "-r", "x", "--bogus"])
add("url_nonjson", "url", ["--apikey", K, "--report", "http://x"], {R("POST", "url/report"): [T("nope")]},
    [urep("http://x")])
add("url_status_500", "url", ["--apikey", K, "--report", "http://x", "--scan", "http://y"],
    {R("POST", "url/report"): [J({"response_code": 0, "verbose_msg": "server error"}, 500)],
     R("POST", "url/scan"): [J({"response_code": 0, "verbose_msg": "Invalid URL"}, 400)]},
    [urep("http://x"), uscan("http://y")])
add("url_drop_crash", "url", ["--apikey", K, "--scan", "http://x"], {R("POST", "url/scan"): [DROP]},
    [uscan("http://x")],
    note="D8: old code segfaults (NULL response after a transfer failure)")
add("url_verbose_msg_null", "url", ["--apikey", K, "--report", "http://x"],
    {R("POST", "url/report"): [J({"response_code": 1, "verbose_msg": None})]}, [urep("http://x")],
    note="D8: old code segfaults on JSON null verbose_msg")

# =============================================================== comments
CG = "comments/get"


def cput(res, comment, key=K):
    return MP("comments/put", P("resource", res), P("comment", comment), P("apikey", key))


add("cm_usage", "comments", [])
add("cm_get_default", "comments", ["--apikey", K, "--resource", "abc"],
    {R("GET", CG): [J({"response_code": 1, "resource": "abc", "comments": [{"date": "20140101120000", "comment": "hi"}],
                       "verbose_msg": "ok"})]},
    [GET(CG, *kq(("resource", "abc")))])
add("cm_get_before", "comments", ["--apikey", K, "--get", "--resource", "abc", "--before", "20140101120000"],
    {R("GET", CG): [J({"response_code": 1, "comments": []})]},
    [GET(CG, *kq(("resource", "abc"), ("before", "20140101120000")))])
add("cm_put", "comments", ["--apikey", K, "--verbose", "--resource", "abc", "--put", "nice #file & stuff"],
    {R("POST", "comments/put"): [J({"response_code": 1, "verbose_msg": "Your comment was successfully posted"})]},
    [cput("abc", "nice #file & stuff")])
add("cm_put_error_json_silent", "comments", ["--apikey", K, "--resource", "abc", "--put", "x"],
    {R("POST", "comments/put"): [J({"response_code": 0, "verbose_msg": "Invalid resource"}, 400)]},
    [cput("abc", "x")])
add("cm_put_before_resource", "comments", ["--apikey", K, "--put", "x", "--resource", "abc"])
add("cm_put_no_apikey", "comments", ["--resource", "abc", "--put", "x"],
    {R("POST", "comments/put"): [J({"response_code": 1})]}, [cput("abc", "x", key="")])
add("cm_put_multi_stray", "comments", ["--apikey", K, "--resource", "abc", "--put", "one", "--put", "two", "trailing"],
    {R("POST", "comments/put"): [J({"response_code": 1})]}, [cput("abc", "one"), cput("abc", "two")])
add("cm_stray_no_retrieve", "comments", ["--apikey", K, "--resource", "abc", "stray"])
add("cm_no_resource", "comments", ["--apikey", K])
add("cm_no_apikey", "comments", ["--resource", "abc"])
add("cm_help", "comments", ["--apikey", K, "--help", "--resource", "abc"])
add("cm_get_nonjson", "comments", ["--apikey", K, "--resource", "abc"], {R("GET", CG): [T("", 204)]},
    [GET(CG, *kq(("resource", "abc")))])
add("cm_get_500", "comments", ["--apikey", K, "--resource", "abc"],
    {R("GET", CG): [J({"response_code": 0, "verbose_msg": "server error"}, 500)]},
    [GET(CG, *kq(("resource", "abc")))])
add("cm_get_response_code_0", "comments", ["--apikey", K, "--resource", "abc"],
    {R("GET", CG): [J({"response_code": 0, "verbose_msg": "resource not found"})]},
    [GET(CG, *kq(("resource", "abc")))])
add("cm_escape_resource", "comments", ["--resource", "h&x=1", "--apikey", K, "--verbose=5"],
    {R("GET", CG): [J({"response_code": 0})]}, [GET(CG, *kq(("resource", "h&x=1")))], note=D4)
add("cm_escape_before_space", "comments", ["--apikey", K, "--resource", "r", "--before", "a b&c"],
    {R("GET", CG): [J({"response_code": 1, "comments": []})]},
    [GET(CG, *kq(("resource", "r"), ("before", "a b&c")))],
    note=D4 + " (old code: curl rejects the space, no request, 'Error: <sprintf count>')")
add("cm_before_drop", "comments", ["--apikey", K, "--resource", "abc", "--before", "2014"],
    {R("GET", CG): [DROP]}, [GET(CG, *kq(("resource", "abc"), ("before", "2014")))])
add("cm_drop_crash", "comments", ["--apikey", K, "--resource", "abc"], {R("GET", CG): [DROP]},
    [GET(CG, *kq(("resource", "abc")))],
    note="D8: old code segfaults (NULL response after a transfer failure)")
add("cm_put_drop", "comments", ["--apikey", K, "--resource", "abc", "--put", "hi"],
    {R("POST", "comments/put"): [DROP]}, [cput("abc", "hi")])
add("cm_before_long", "comments", ["--apikey", K, "--resource", "abc", "--before", "9" * 700],
    {R("GET", CG): [J({"response_code": 1, "comments": []})]},
    [GET(CG, *kq(("resource", "abc"), ("before", "9" * 700)))],
    note="D8: old code overflows its stack buffer (sprintf) and aborts")
add("cm_resource_long", "comments", ["--apikey", K, "--resource", "r" * 600],
    {R("GET", CG): [J({"response_code": 1, "comments": []})]},
    [GET(CG, *kq(("resource", "r" * 600)))], note="D8: long inputs must not be truncated")
add("cm_verbose_msg_null", "comments", ["--apikey", K, "--resource", "abc"],
    {R("GET", CG): [J({"response_code": 1, "verbose_msg": None})]}, [GET(CG, *kq(("resource", "abc")))],
    note="D8: old code segfaults on JSON null verbose_msg")

# ============================================================ distribution
FD = "file/distribution"
UD = "url/distribution"
D8S = "D8: after a failed request the dist tools must return an error and must not re-process the previous page (old code re-parses the stale response and keeps looping)"


def fdq(*extra, key=K):
    return GET(FD, ("apikey", key), *extra)


def udq(*extra, key=K):
    return GET(UD, ("apikey", key), *extra)


def fitem(ts, link="https://dl/x", sha="aa", **kw):
    d = {"link": link, "timestamp": ts, "sha256": sha}
    d.update(kw)
    return d


def uitem(ts, url="http://u/", total=60, positives=1, **kw):
    d = {"url": url, "timestamp": ts, "total": total, "positives": positives}
    d.update(kw)
    return d


S0 = ["--sleep", "0"]
add("fd_usage", "file_dist", [])
add("fd_paging", "file_dist",
    ["--apikey", K, "--limit", "5", "--reports", "1", "--sleep", "0", "--repeat", "4", "--before", "1", "--after", "2"],
    {R("GET", FD): [J([fitem(1400000001, "https://dl/1", "aa", name="a.exe", extra={"k": 1}),
                       fitem(1400000000, "https://dl/2", "bb")]),
                    J([fitem(1400000005, "https://dl/3", "cc", name="c")]), J([])]},
    [fdq(("reports", "true"), ("limit", "5")),
     fdq(("after", "1400000000"), ("reports", "true"), ("limit", "5")),
     fdq(("after", "1400000005"), ("reports", "true"), ("limit", "5")),
     fdq(("after", "1400000005"), ("reports", "true"), ("limit", "5"))])
add("fd_defaults_sleep", "file_dist", ["--apikey", K], {R("GET", FD): [J([])]}, [fdq()] * 3, timeout=30)
add("fd_sleep_1", "file_dist", ["--apikey", K, "--repeat", "2", "--sleep", "1"],
    {R("GET", FD): [J([fitem(7)]), J([])]}, [fdq(), fdq(("after", "7"))])
add("fd_not_array", "file_dist", ["--apikey", K] + S0 + ["--repeat", "2"],
    {R("GET", FD): [J({"response_code": 0})]}, [fdq()])
add("fd_elem_not_object", "file_dist", ["--apikey", K] + S0 + ["--repeat", "1"], {R("GET", FD): [J([1])]}, [fdq()])
add("fd_missing_link", "file_dist", ["--apikey", K] + S0 + ["--repeat", "1"],
    {R("GET", FD): [J([{"sha256": "s", "timestamp": 1}])]}, [fdq()])
add("fd_partial_missing_sha256", "file_dist", ["--apikey", K] + S0 + ["--repeat", "2"],
    {R("GET", FD): [J([fitem(7, "l", "s"), {"link": "m", "timestamp": 8}])]}, [fdq()])
add("fd_bad_timestamp", "file_dist", ["--apikey", K] + S0 + ["--repeat", "1"],
    {R("GET", FD): [J([{"link": "l", "sha256": "s", "timestamp": "1"}])]}, [fdq()])
add("fd_limit_reports_edge", "file_dist", ["--apikey", K] + S0 + ["--repeat", "2", "--limit", "-3", "--reports", "yes"],
    {R("GET", FD): [J([{"link": "l", "sha256": "s", "timestamp": 5, "name": 7}]), J([])]},
    [fdq(("limit", "-3")), fdq(("after", "5"), ("limit", "-3"))])
add("fd_nonjson", "file_dist", ["--apikey", K] + S0, {R("GET", FD): [T("oops")]}, [fdq()])
add("fd_http_500", "file_dist", ["--apikey", K] + S0 + ["--repeat", "3"],
    {R("GET", FD): [J([fitem(9)]), J({"response_code": 0}, 500)]}, [fdq(), fdq(("after", "9"))])
add("fd_repeat_zero", "file_dist", ["--apikey", K, "--repeat", "0"])
add("fd_negative_repeat", "file_dist", ["--apikey", K, "--repeat", "-1"] + S0,
    {R("GET", FD): [J([]), J([]), J([]), J([]), J({}, 500)]}, [fdq()] * 5)
add("fd_help", "file_dist", ["--apikey", K, "--help"])
add("fd_stray_and_unknown", "file_dist", ["--apikey", K] + S0 + ["--repeat", "1", "--verbose=2", "--allinfo", "1", "stray"],
    {R("GET", FD): [J([])]}, [fdq()])
add("fd_stale_reparse", "file_dist", ["--apikey", K] + S0 + ["--repeat", "3"],
    {R("GET", FD): [J([fitem(0, "l", "s", name="n")]), DROP, J([])]}, [fdq(), fdq()], note=D8S)
add("fd_drop_with_after", "file_dist", ["--apikey", K] + S0 + ["--repeat", "3"],
    {R("GET", FD): [J([fitem(1400000000, "l", "s")]), DROP, J([])]}, [fdq(), fdq(("after", "1400000000"))])
add("fd_drop_first", "file_dist", ["--apikey", K] + S0 + ["--repeat", "2"], {R("GET", FD): [DROP, J([])]}, [fdq()])
add("fd_long_apikey", "file_dist", ["--apikey", "k" * 470, "--limit", "1000", "--reports", "1"] + S0 + ["--repeat", "1"],
    {R("GET", FD): [J([])]}, [fdq(("reports", "true"), ("limit", "1000"), key="k" * 470)],
    note="D8: long api keys must not overflow/truncate the URL (old code stack-overflows char[512])")
add("fd_escape_apikey", "file_dist", ["--apikey", "K&x=1", "--repeat", "1"] + S0,
    {R("GET", FD): [J([])]}, [fdq(key="K&x=1")], note=D4)
add("fd_chunked", "file_dist", ["--apikey", K, "--repeat", "1"] + S0,
    {R("GET", FD): [J([fitem(100 + i, "https://dl/%d" % i, "%064x" % i) for i in range(50)], chunks=11)]},
    [fdq()])

add("ud_usage", "url_dist", [])
add("ud_paging", "url_dist",
    ["--apikey", K, "--allinfo", "1", "--limit", "10", "--sleep", "0", "--repeat", "5", "--before", "9", "--after", "9",
     "--all-info"],
    {R("GET", UD): [J([uitem(1500000002, "http://a/", 60, 2, scans={}), uitem(1500000001, "http://b/", 61, 0)]),
                    J([]), T("", 403)]},
    [udq(("allinfo", "true"), ("limit", "10")),
     udq(("after", "1500000001"), ("allinfo", "true"), ("limit", "10")),
     udq(("after", "1500000001"), ("allinfo", "true"), ("limit", "10"))])
add("ud_defaults", "url_dist", ["--apikey", K], {R("GET", UD): [J([])]}, [udq()] * 3, timeout=30)
add("ud_allinfo_zero", "url_dist", ["--apikey", K, "--allinfo", "0", "--verbose=4"] + S0 + ["--repeat", "1"],
    {R("GET", UD): [J([uitem(1, "u", 1, 1)])]}, [udq()])
add("ud_not_array", "url_dist", ["--apikey", K] + S0 + ["--repeat", "1"], {R("GET", UD): [J({"x": 1})]}, [udq()])
add("ud_elem_not_object", "url_dist", ["--apikey", K] + S0 + ["--repeat", "1"], {R("GET", UD): [J(["x"])]}, [udq()])
add("ud_missing_url", "url_dist", ["--apikey", K] + S0 + ["--repeat", "1"], {R("GET", UD): [J([{"timestamp": 1}])]}, [udq()])
add("ud_bad_timestamp", "url_dist", ["--apikey", K] + S0 + ["--repeat", "1"],
    {R("GET", UD): [J([{"url": "u", "timestamp": 1.5}])]}, [udq()])
add("ud_missing_total", "url_dist", ["--apikey", K] + S0 + ["--repeat", "1"],
    {R("GET", UD): [J([{"url": "u", "timestamp": 1, "positives": 1}])]}, [udq()])
add("ud_missing_positives", "url_dist", ["--apikey", K] + S0 + ["--repeat", "1"],
    {R("GET", UD): [J([{"url": "u", "timestamp": 1, "total": 1}])]}, [udq()])
add("ud_nonjson", "url_dist", ["--apikey", K] + S0 + ["--repeat", "1"], {R("GET", UD): [T("x")]}, [udq()])
add("ud_drop_with_after", "url_dist", ["--apikey", K] + S0 + ["--repeat", "3"],
    {R("GET", UD): [J([uitem(5, "u", 1, 0)]), DROP, J([])]}, [udq(), udq(("after", "5"))])
add("ud_stale_reparse", "url_dist", ["--apikey", K] + S0 + ["--repeat", "3"],
    {R("GET", UD): [J([uitem(0, "u", 1, 0)]), DROP, J([])]}, [udq(), udq()], note=D8S)
add("ud_drop_first", "url_dist", ["--apikey", K] + S0 + ["--repeat", "2"], {R("GET", UD): [DROP, J([])]}, [udq()])
add("ud_help", "url_dist", ["--help", "--apikey", K])
add("ud_long_apikey", "url_dist", ["--apikey", "k" * 470, "--limit", "1000", "--allinfo", "1"] + S0 + ["--repeat", "1"],
    {R("GET", UD): [J([])]}, [udq(("allinfo", "true"), ("limit", "1000"), key="k" * 470)],
    note="D8: long api keys must not overflow/truncate the URL (old code stack-overflows char[512])")
add("ud_escape_apikey", "url_dist", ["--apikey", "K&x=1", "--repeat", "1"] + S0,
    {R("GET", UD): [J([])]}, [udq(key="K&x=1")], note=D4)
add("ud_negative_repeat", "url_dist", ["--apikey", K, "--repeat", "-2"] + S0,
    {R("GET", UD): [J([uitem(3)]), J([]), J({}, 500)]}, [udq(), udq(("after", "3")), udq(("after", "3"))])

# ================================================================ vtprobe
NOTIFY = "http://notify.example/cb?a=1&b=2"
DATE = 1400000000
DATESTR = datetime.datetime.fromtimestamp(DATE, datetime.timezone.utc).strftime("%Y%m%d%H%M%S")


def rescan_req(h, date=None, period=None, repeat=None, notify=None, changes=False):
    parts = [P("resource", h)]
    if date:
        parts.append(P("date", date))
    if period:
        parts.append(P("period", str(period)))
    if repeat:
        parts.append(P("repeat", str(repeat)))
    if notify:
        parts.append(P("notify_url", notify))
        if changes:
            parts.append(P("notify_changes_only", "1"))
    parts.append(P("apikey", K))
    return MP("file/rescan", *parts)


RS = {R("POST", "file/rescan"): [J({"response_code": 1, "verbose_msg": "Rescan queued", "scan_id": "s"})]}
add("probe_rescan_delete", "vtprobe", ["rescan_delete", K, H32],
    {R("POST", "file/rescan/delete"): [J({"response_code": 1, "verbose_msg": "deleted"})]},
    [MP("file/rescan/delete", P("resource", H32), P("apikey", K))])
add("probe_rescan_delete_500", "vtprobe", ["rescan_delete", K, H32],
    {R("POST", "file/rescan/delete"): [J({"response_code": 0}, 500)]},
    [MP("file/rescan/delete", P("resource", H32), P("apikey", K))])
add("probe_rescan_all", "vtprobe", ["rescan", K, H32, str(DATE), "7", "3", NOTIFY, "1"], RS,
    [rescan_req(H32, DATESTR, 7, 3, NOTIFY, True)])
add("probe_rescan_notify_only", "vtprobe", ["rescan", K, H32, "0", "0", "0", NOTIFY, "0"], RS,
    [rescan_req(H32, notify=NOTIFY)])
add("probe_rescan_changes_without_notify", "vtprobe", ["rescan", K, H32, "0", "0", "0", "-", "1"], RS,
    [rescan_req(H32)])
add("probe_rescan_date_only", "vtprobe", ["rescan", K, H32, "86399", "0", "0", "-", "0"], RS,
    [rescan_req(H32, "19700101235959")])
add("probe_rescan_period_repeat", "vtprobe", ["rescan", K, H32, "0", "30", "2", "-", "0"], RS,
    [rescan_req(H32, period=30, repeat=2)])
add("probe_scan_notify", "vtprobe", ["scan", K, "inputs/sample.bin", "http://notify.example/x"],
    {R("POST", "file/scan"): [J(OK)]}, [scan_file_req("inputs/sample.bin", SAMPLE, notify="http://notify.example/x")],
    note=D1, inputs={"sample.bin": SAMPLE})
add("probe_scan_empty_notify", "vtprobe", ["scan", K, "inputs/sample.bin", ""],
    {R("POST", "file/scan"): [J(OK)]}, [scan_file_req("inputs/sample.bin", SAMPLE)],
    note=D1, inputs={"sample.bin": SAMPLE})
MEMDATA = gen_bytes(3000, "membuf")
add("probe_scan_membuf_notify", "vtprobe", ["scan_membuf", K, "decoy.bin", "data.bin", "http://notify.example/y"],
    {R("POST", "file/scan"): [J(OK)]},
    [MP("file/scan", F("file", "decoy.bin", MEMDATA), P("notify_url", "http://notify.example/y"), P("apikey", K))],
    note=D2, inputs={"decoy.bin": b"DECOY-DISK-CONTENT", "data.bin": MEMDATA}, inputs_at_cwd=True)
add("probe_scan_membuf_no_notify", "vtprobe", ["scan_membuf", K, "decoy.bin", "data.bin", "-"],
    {R("POST", "file/scan"): [J(OK)]},
    [MP("file/scan", F("file", "decoy.bin", MEMDATA), P("apikey", K))],
    note=D2, inputs={"decoy.bin": b"DECOY-DISK-CONTENT", "data.bin": MEMDATA}, inputs_at_cwd=True)
add("probe_scan_membuf_limit", "vtprobe", ["scan_membuf", K, "decoy.bin", "inputs/data32.bin", "-"],
    {R("POST", "file/scan"): [J(OK)]}, [],
    gen=[{"path": "inputs/data32.bin", "size": 32 * MiB, "seed": "m32"}], timeout=60)
add("probe_scan_membuf_no_filename", "vtprobe", ["scan_membuf", K, "-", "data.bin", "-"],
    {R("POST", "file/scan"): [J(OK)]}, [], inputs={"data.bin": MEMDATA}, inputs_at_cwd=True)
add("probe_scan_bigfile_small", "vtprobe", ["scan_bigfile", K, "inputs/sample.bin"],
    {R("GET", "file/scan/upload_url"): [J({"upload_url": "{MOCK}/_ah/upload/P/"})],
     R("POST", "/_ah/upload/P/"): [J({"response_code": 1, "verbose_msg": "queued"})]},
    [GET("file/scan/upload_url", ("apikey", K)), upload("/_ah/upload/P/", "inputs/sample.bin", SAMPLE)],
    note=D3, inputs={"sample.bin": SAMPLE})
add("probe_upload_url_ok", "vtprobe", ["upload_url", K],
    {R("GET", "file/scan/upload_url"): [J({"upload_url": "{MOCK}/_ah/upload/Z/"})]},
    [GET("file/scan/upload_url", ("apikey", K))])
add("probe_upload_url_missing_key", "vtprobe", ["upload_url", K],
    {R("GET", "file/scan/upload_url"): [J({})]}, [GET("file/scan/upload_url", ("apikey", K))])
add("probe_upload_url_escape", "vtprobe", ["upload_url", "K&x=1"],
    {R("GET", "file/scan/upload_url"): [J({"upload_url": "{MOCK}/_ah/upload/Z/"})]},
    [GET("file/scan/upload_url", ("apikey", "K&x=1"))], note=D4)
add("probe_cancel_report", "vtprobe", ["cancel_report", K, "R1", "R2"],
    {R("POST", "file/report"): [J(OK)]}, [rep("R1"), rep("R2")],
    note="D7: cancel is reset at the start of each operation (old code: a cancel issued before an operation aborts it and every later operation, so nothing is sent)")
add("probe_search_seq_no_autothread", "vtprobe", ["search_seq", K, "q", "START", "-"],
    {R("POST", "file/search"): [J({"offset": "P2", "hashes": ["a"]}), J({"hashes": ["b"]})]},
    [srch("q", "START"), srch("q")])
add("probe_search_seq_next", "vtprobe", ["search_seq", K, "q", "START", "@next", "@next", "@next"],
    {R("POST", "file/search"): [J({"offset": "P2", "hashes": ["a"]}), J({"hashes": ["b"]}),
                                J({"offset": "P4", "hashes": ["c"]}), J({"hashes": []})]},
    [srch("q", "START"), srch("q", "P2"), srch("q"), srch("q", "P4")], note=D9)
add("probe_file_dist_before_after", "vtprobe", ["file_dist", K, "1500000000", "1400000000", "1", "20", "2"],
    {R("GET", FD): [J([fitem(1400000100, "l", "s")]), J([])]},
    [fdq(("before", "1500000000"), ("after", "1400000000"), ("reports", "true"), ("limit", "20")),
     fdq(("before", "1500000000"), ("after", "1400000100"), ("reports", "true"), ("limit", "20"))])
add("probe_url_dist_before_after", "vtprobe", ["url_dist", K, "1500000000", "1400000000", "1", "20", "2"],
    {R("GET", UD): [J([uitem(1400000100)]), J([])]},
    [udq(("before", "1500000000"), ("after", "1400000000"), ("allinfo", "true"), ("limit", "20")),
     udq(("before", "1500000000"), ("after", "1400000100"), ("allinfo", "true"), ("limit", "20"))])
add("probe_url_report_scan_only", "vtprobe", ["url_report", K, "http://x", "1", "0"],
    {R("POST", "url/report"): [J(OK)]}, [urep("http://x", "scan")])
add("probe_url_report_all_info_only", "vtprobe", ["url_report", K, "http://x", "0", "1"],
    {R("POST", "url/report"): [J(OK)]}, [urep("http://x", "all_info")])


# ============================================ VT_API_BASE_URL override (D11)
D11 = "D11: the tools must honour VT_API_BASE_URL (old code has the base URL compiled in)"
ALT = "{MOCK}/alt/v2/"  # run.py substitutes {MOCK}/{PORT} in env values
add("base_url_env_ip", "ip", ["--apikey", K, "--report", "1.2.3.4"],
    {R("GET", "/alt/v2/ip-address/report"): [J(OK)]},
    [GET("/alt/v2/ip-address/report", *kq(("ip", "1.2.3.4")))], note=D11, env={"VT_API_BASE_URL": ALT})
add("base_url_env_scan_report", "scan", ["--apikey", K, "--report", "R", "--clusters", "2024-01-01"],
    {R("POST", "/alt/v2/file/report"): [J(OK)], R("GET", "/alt/v2/file/clusters"): [J({"clusters": []})]},
    [MP("/alt/v2/file/report", P("resource", "R"), P("apikey", K)),
     GET("/alt/v2/file/clusters", *kq(("date", "2024-01-01")))], note=D11, env={"VT_API_BASE_URL": ALT})
add("base_url_env_url_dist", "url_dist", ["--apikey", K, "--repeat", "1"] + S0,
    {R("GET", "/alt/v2/url/distribution"): [J([])]},
    [GET("/alt/v2/url/distribution", *kq())], note=D11, env={"VT_API_BASE_URL": ALT})


# ------------------------------------------------------------------ write
def write_all(out: Path):
    """(Re)create `out` with one directory per scenario; returns the ids."""
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    for sid, s in SC.items():
        d = out / sid
        d.mkdir(parents=True)
        sc = {"tool": s["tool"], "argv": s["argv"], "timeout": s["timeout"]}
        sc.update(s["extra"])
        (d / "scenario.json").write_text(json.dumps(sc, indent=1, ensure_ascii=False) + "\n")
        cfg = {"routes": s["routes"]}
        if s["default"] is not None:
            cfg["default"] = s["default"]
        (d / "config.json").write_text(json.dumps(cfg, indent=1) + "\n")
        if s["inputs"]:
            (d / "inputs").mkdir()
            for name, data in s["inputs"].items():
                (d / "inputs" / name).write_bytes(data)
        model = {"requests": s["expect"], "files": s["files"]}
        if s["note"]:
            model["note"] = s["note"]
        (d / "expect.json").write_text(json.dumps(model, indent=1, ensure_ascii=False) + "\n")
    return list(SC)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True, help="directory to (re)create")
    a = ap.parse_args(argv)
    ids = write_all(Path(a.out))
    print(f"{len(ids)} scenarios written to {a.out}")


if __name__ == "__main__":
    main()
