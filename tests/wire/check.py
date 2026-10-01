#!/usr/bin/env python3
"""Compare what a tool did in each scenario against the model.

For every scenario the recorded requests (results/<id>/requests.jsonl,
written by the mock) must equal the model (scenarios/<id>/expect.json
"requests"): method, path, decoded query pairs, request headers (except
Host and the framing ones; a model request without "headers" means exactly
"Accept: */*"), content type, form pairs, multipart parts (name, filename,
Content-Type, len + sha256 of the content) and any other body (len +
sha256).  Everything is compared in order: requests, query / form pairs and
multipart parts.  Only chunked transfer encoding is ignored.  A model
"connections" list (one label per request) must match which requests
shared a connection: equal labels <=> same connection.

The files the tool created in its working directory (results/<id>/
files.json, written by run.py) must equal the model's "files" exactly
(names, len + sha256).  The exit status must equal the model's "exit"
(a negative value is death by that signal).  Stdout must equal the golden
file scenarios/<id>/stdout (from tests/wire/golden/<id>.stdout) after
dropping the nondeterministic "progress_callback N/M" lines and writing the
mock's origin http://127.0.0.1:<port> as {MOCK}.  Stderr is not compared,
but a sanitizer report in it (AddressSanitizer, LeakSanitizer,
UndefinedBehaviorSanitizer) fails the scenario.  A tool that is missing or
hits the scenario timeout fails it too.

Standalone use on an existing results tree:
    check.py --scenarios WORK/scenarios --results WORK/results [--only ID...]
"""
import argparse
import difflib
import hashlib
import json
import re
import signal
from pathlib import Path

PROGRESS = re.compile(rb"^progress_callback -?[0-9]+/-?[0-9]+$")
SANITIZER_MARKS = (b"ERROR: AddressSanitizer", b"ERROR: LeakSanitizer", b"runtime error:",
                   b"SUMMARY: UndefinedBehaviorSanitizer")


# ------------------------------------------------------------ normalise
def _blob(d):
    return {"len": d["len"], "sha256": d["sha256"]}


def _pairs(pairs):
    return [tuple(p) for p in pairs]


def norm_req(req):
    r = dict(req)
    for k in ("seq", "conn", "chunked"):
        r.pop(k, None)
    r["headers"] = dict(r.get("headers", {"accept": "*/*"}))
    r["query"] = _pairs(r.get("query", []))
    if "form" in r:
        r["form"] = _pairs(r["form"])
    if "body" in r:
        r["body"] = _blob(r["body"])
    if "multipart" in r:
        parts = []
        for p in r["multipart"]:
            p = dict(p)
            p["data"] = _blob(p["data"])
            parts.append(p)
        r["multipart"] = parts
    return r


def norm_files(files):
    return {k: _blob(v) for k, v in files.items()}


def norm_stdout(data: bytes, origin=None, argv0=None, want_argv0=None):
    """Drops the progress_callback lines, writes the mock origin as {MOCK}
    and a wrapper's argv[0] (the tool's path) as the scenario's argv0."""
    if origin:
        data = data.replace(origin.encode(), b"{MOCK}")
    if argv0 and want_argv0 and argv0 != want_argv0:
        data = data.replace(argv0.encode("utf-8", "surrogateescape"), want_argv0.encode())
    return b"\n".join(line for line in data.split(b"\n") if not PROGRESS.match(line))


def result_stdout(sdir: Path, rdir: Path):
    """The normalised stdout of a run (see norm_stdout)."""
    sc = json.loads((sdir / "scenario.json").read_text(encoding="utf-8"))
    so = rdir / "stdout"
    return norm_stdout(so.read_bytes() if so.exists() else b"", read_opt(rdir / "origin"),
                       read_opt(rdir / "argv0"), sc.get("argv0", sc["tool"]))


def same_grouping(labels, conns):
    """labels[i] == labels[j] exactly when conns[i] == conns[j]."""
    return len(labels) == len(conns) and all(
        (labels[i] == labels[j]) == (conns[i] == conns[j])
        for i in range(len(labels)) for j in range(len(labels)))


# --------------------------------------------------------------- render
def _texts(*objs):
    """sha256 -> decoded text, from every blob that carries one."""
    out = {}

    def walk(o):
        if isinstance(o, dict):
            if "sha256" in o and "text" in o:
                out[o["sha256"]] = o["text"]
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    for o in objs:
        walk(o)
    return out


def fmt_str(s):
    if len(s) <= 60 and s.isprintable():
        return json.dumps(s, ensure_ascii=False)
    h = hashlib.sha256(s.encode("utf-8", "surrogateescape")).hexdigest()[:12]
    return "%s...%s (%d chars, sha256 %s)" % (json.dumps(s[:24], ensure_ascii=False)[:-1],
                                              json.dumps(s[-8:], ensure_ascii=False)[1:], len(s), h)


def fmt_blob(d, texts):
    t = texts.get(d["sha256"])
    if t is not None:
        return fmt_str(t)
    return "<%d bytes, sha256 %s>" % (d["len"], d["sha256"][:12])


def render_reqs(reqs, texts):
    lines = []
    for r in reqs:
        lines.append("%s %s" % (r.get("method"), r.get("path")))
        for k, v in r.get("query", []):
            lines.append("    query  %s=%s" % (k, fmt_str(v)))
        if "content_type" in r:
            lines.append("    ctype  %s" % r["content_type"])
        for k, v in r.get("form", []):
            lines.append("    form   %s=%s" % (k, fmt_str(v)))
        for p in r.get("multipart", []):
            keys = sorted(set(p) - {"data"}, key=lambda k: ({"name": 0, "filename": 1}.get(k, 2), k))
            attrs = " ".join("%s=%s" % (k, fmt_str(str(p[k]))) for k in keys)
            lines.append("    part   %s data=%s" % (attrs or "(no name)", fmt_blob(p["data"], texts)))
        if "body" in r:
            lines.append("    body   %s" % fmt_blob(r["body"], texts))
        for k in sorted(set(r) - {"method", "path", "query", "content_type", "form", "multipart", "body"}):
            lines.append("    %s: %s" % (k, json.dumps(r[k], sort_keys=True)))
    return lines


def render_files(files, texts):
    return ["file %s %s" % (k, fmt_blob(v, texts)) for k, v in sorted(files.items())]


def text_lines(data: bytes):
    return data.decode("utf-8", "backslashreplace").split("\n")


def udiff(exp_lines, got_lines, what):
    return list(difflib.unified_diff(exp_lines, got_lines, "expected %s (model)" % what,
                                     "recorded %s" % what, n=2, lineterm=""))


# ---------------------------------------------------------------- check
def load_jsonl(p: Path):
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_opt(p: Path):
    return p.read_text(encoding="utf-8").strip() if p.exists() else None


def exit_info(code):
    if code.lstrip("-").isdigit() and int(code) < 0:
        try:
            return "killed by %s" % signal.Signals(-int(code)).name
        except ValueError:
            return "killed by signal %s" % -int(code)
    return "exit %s" % code


def check_one(sdir: Path, rdir: Path):
    """Returns (ok, status_suffix, detail_lines)."""
    model = json.loads((sdir / "expect.json").read_text(encoding="utf-8"))
    sc = json.loads((sdir / "scenario.json").read_text(encoding="utf-8"))
    code = read_opt(rdir / "exit") or "not-run"
    secs = read_opt(rdir / "time") or "?"
    problems = []
    ran = code.lstrip("-").isdigit()
    if code == "not-run":
        problems.append("scenario was not run (no results)")
    elif code == "missing-tool":
        problems.append("tool '%s' was not provided (--tool/--probe/--bindir)" % sc["tool"])
    elif code.startswith("runner-error"):
        problems.append(code)
    elif code == "timeout":
        problems.append("tool did not finish within its %ss timeout" % sc.get("timeout"))
    elif not ran:
        problems.append("unexpected exit record %r" % code)
    elif int(code) != model.get("exit", 0):
        problems.append("tool ended with %s, expected %s" % (
            exit_info(code), exit_info(str(model.get("exit", 0)))))
    detail = []

    got_raw = load_jsonl(rdir / "requests.jsonl")
    exp = [norm_req(x) for x in model["requests"]]
    got = [norm_req(x) for x in got_raw]
    files_path = rdir / "files.json"
    got_files_raw = json.loads(files_path.read_text(encoding="utf-8")) if files_path.exists() else {}
    texts = _texts(model, got_raw, got_files_raw)
    if exp != got:
        problems.append("requests differ (expected %d, recorded %d)" % (len(exp), len(got)))
        detail += udiff(render_reqs(exp, texts), render_reqs(got, texts), "requests")
    elif "connections" in model and not same_grouping(model["connections"],
                                                      [r.get("conn") for r in got_raw]):
        problems.append("connection reuse differs: model %s, recorded connections %s" % (
            model["connections"], [r.get("conn") for r in got_raw]))
    ef, gf = norm_files(model.get("files", {})), norm_files(got_files_raw)
    if code != "missing-tool" and ef != gf:
        problems.append("created files differ")
        detail += udiff(render_files(ef, texts), render_files(gf, texts), "files")
    if ran:
        golden = sdir / "stdout"
        got_out = result_stdout(sdir, rdir)
        if not golden.exists():
            problems.append("no golden stdout (tests/wire/golden/%s.stdout; run.py --update-golden)"
                            % sdir.name)
        elif got_out != golden.read_bytes():
            problems.append("stdout differs from the golden file")
            detail += udiff(text_lines(golden.read_bytes()), text_lines(got_out), "stdout")
        se = rdir / "stderr"
        marks = [m.decode() for m in SANITIZER_MARKS if se.exists() and m in se.read_bytes()]
        if marks:
            problems.append("sanitizer reported errors (%s), see %s" % (", ".join(marks), se))
    status = "(%s, %s, %ss)" % (sc["tool"], exit_info(code), secs)
    if not problems:
        return True, status, []
    lines = ["    " + p for p in problems]
    if model.get("note"):
        lines.append("    note: " + model["note"])
    lines += ["    " + d for d in detail]
    return False, status, lines


def check(scen_root: Path, res_root: Path, ids, quiet=False, out=print):
    fails = []
    for i in ids:
        ok, status, lines = check_one(scen_root / i, res_root / i)
        if not ok:
            fails.append((i, status, lines))
        if not quiet or not ok:
            out("%s %s %s" % ("ok  " if ok else "FAIL", i, status))
    return fails


def report(fails, total, out=print):
    if fails:
        out("")
        out("=" * 72)
        for i, status, lines in fails:
            out("FAIL %s %s" % (i, status))
            for line in lines:
                out(line)
            out("")
    out("%d scenario(s): %d passed, %d failed%s" % (
        total, total - len(fails), len(fails),
        (": " + " ".join(i for i, _, _ in fails)) if fails else ""))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scenarios", required=True, type=Path)
    ap.add_argument("--results", required=True, type=Path)
    ap.add_argument("--only", nargs="*", help="restrict to these scenario ids")
    ap.add_argument("-q", "--quiet", action="store_true", help="print failing scenarios only")
    a = ap.parse_args()
    ids = sorted(d.name for d in a.scenarios.iterdir() if (d / "expect.json").exists())
    if a.only:
        ids = [i for i in ids if i in a.only]
    fails = check(a.scenarios, a.results, ids, a.quiet)
    report(fails, len(ids))
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
