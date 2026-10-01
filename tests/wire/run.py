#!/usr/bin/env python3
"""Wire-level regression suite: run every scenario, then check it.

  run.py --workdir DIR (--bindir BINDIR | --tool NAME=PATH ... --probe PATH)
         [--only ID ...] [--jobs N] [--port N] [--wrapper CMD] [-q]
         [--update-golden]

1. gen_scenarios.py writes the scenarios (+ model) to DIR/scenarios/.
2. Each scenario runs its tool (one of scan search ip domain_report url
   comments file_dist url_dist, or the library driver vtprobe) in a fresh
   cwd DIR/results/<id>/cwd against its own recording mock (mockvt.py).
   The mock listens on a kernel-chosen free port and the tool gets
   VT_API_BASE_URL=http://127.0.0.1:<port>/vtapi/v2/, so runs never collide
   with each other or with other test suites.  Scenario env values may use
   {MOCK} (http://127.0.0.1:<port>) and {PORT}.  "no_mock" scenarios get a
   port that is bound but not listening (connection refused).  The tools
   also get TZ=XYZ-5:30, a non-UTC zone, so a local-time bug shows on UTC
   hosts too.
3. check.py compares recorded requests, created files, exit status and
   stdout with the model and the golden stdout, and fails a scenario whose
   stderr holds a sanitizer report.
Exit status 0 when every selected scenario passes, 1 otherwise, 2 on usage
errors.

--update-golden writes the stdout of every scenario that ran (normalised as
check.py compares it) to tests/wire/golden/<id>.stdout; review the result
with git diff.

--port N pins the mock to port N (for old builds with a compiled-in base
URL); it implies --jobs 1 and waits while the port is busy.

--wrapper CMD runs every tool as `CMD... TOOL ARGS` (CMD is split like a
shell command line), e.g. under valgrind:
  --wrapper 'valgrind -q --error-exitcode=99 --leak-check=full
             --errors-for-leak-kinds=definite,indirect' --wrapper-exit 99
argv[0] is then the tool's path, which the stdout comparison maps back to
the scenario's argv0.  --wrapper-exit N makes a scenario whose tool exits
with status N fail, so the wrapper's own error exit status is reported.

scenario.json keys: tool, argv, timeout (seconds) and optionally
  "argv0"       argv[0] seen by the tool (default: the tool name)
  "env"         extra environment ({MOCK}/{PORT} substituted)
  "stdin" / "stdin_b64" / "stdin_gen": {"size": N, "seed": "s"}
  "gen": [{"path": "inputs/big.bin", "size": N, "seed": "s"}]
                generated input files (gen_util.py), deleted after the run
  "inputs_at_cwd": true   copy inputs/* into the cwd itself (default:
                cwd/inputs/)
  "no_mock": true         connection refused
  "stdin_hold": true      stdin is a pipe that stays open (and empty) until
                the tool exits
  "stdout_closed": true   stdout is a pipe whose reader has already exited
  "signal": {"name": "SIGTERM", "after_requests": 1, "delay": 0.3}
                send a signal `delay` seconds after the mock has logged N
                requests (with N = 0, after the start: that delay is scaled
                by --timeout-mult, as the tool's start-up is); a list of
                names is delivered together (sent while the tool is stopped)
"""
import argparse
import base64
import concurrent.futures
import errno
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True  # keep the source tree clean
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
import gen_scenarios  # noqa: E402
from gen_util import blob, gen_bytes, write_gen  # noqa: E402
from mockvt import MockServer  # noqa: E402

TOOLS = ["scan", "search", "ip", "domain_report", "url", "comments", "file_dist", "url_dist"]
PROBE = "vtprobe"
# never inherited by the tools: proxies would divert the loopback requests,
# the rest changes behaviour that scenarios pin explicitly
SCRUB_ENV = ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY",
             "POSIXLY_CORRECT", "VT_API_BASE_URL", "VT_DEBUG"]


class PortBusy(Exception):
    pass


def with_port(fn, port, wait, log):
    """fn(port) -> object; retry while a fixed port is in use."""
    t_end = time.time() + wait
    warned = False
    while True:
        try:
            return fn(port)
        except OSError as e:
            if port == 0 or e.errno != errno.EADDRINUSE:
                raise
            if time.time() >= t_end:
                raise PortBusy("port %d still busy after %ds" % (port, wait))
            if not warned:
                log("port %d is busy, waiting for it (up to %ds)..." % (port, wait))
                warned = True
            time.sleep(1)


def hold_port(port):
    """A bound, non-listening socket: connections to it are refused and no
    one else can listen on the port while we hold it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        s.close()
        raise
    return s


def tool_env(origin, port, sc_env):
    env = dict(os.environ)
    for k in SCRUB_ENV:
        env.pop(k, None)
    env["no_proxy"] = env["NO_PROXY"] = "*"
    # a POSIX zone (no tzdata needed) that is not UTC, with a half-hour
    # offset: a rescan date formatted in local time differs on any host
    env["TZ"] = "XYZ-5:30"
    env["VT_API_BASE_URL"] = origin + "/vtapi/v2/"
    for k, v in sc_env.items():
        env[k] = v.replace("{MOCK}", origin).replace("{PORT}", str(port))
    return env


def send_signals(p, sig):
    names = sig["name"] if isinstance(sig["name"], list) else [sig["name"]]
    if len(names) > 1:  # stopped, the tool receives them all at once
        p.send_signal(signal.SIGSTOP)
    for n in names:
        p.send_signal(getattr(signal, n))
    if len(names) > 1:
        p.send_signal(signal.SIGCONT)


def run_one(sdir: Path, rdir: Path, tools, a, log):
    sc = json.loads((sdir / "scenario.json").read_text(encoding="utf-8"))
    if rdir.exists():
        shutil.rmtree(rdir)
    work = rdir / "cwd"
    if (sdir / "inputs").exists():
        shutil.copytree(sdir / "inputs", work if sc.get("inputs_at_cwd") else work / "inputs")
    else:
        (work / "inputs").mkdir(parents=True)
    work.mkdir(parents=True, exist_ok=True)
    for g in sc.get("gen", []):
        dst = work / g["path"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        write_gen(dst, g["size"], g["seed"])
    before = {p.relative_to(work) for p in work.rglob("*")}

    if "stdin_gen" in sc:
        stdin = gen_bytes(sc["stdin_gen"]["size"], sc["stdin_gen"]["seed"])
    elif "stdin_b64" in sc:
        stdin = base64.b64decode(sc["stdin_b64"])
    else:
        stdin = sc.get("stdin", "").encode()

    reqlog = rdir / "requests.jsonl"
    exe = tools.get(sc["tool"])
    t0 = time.time()
    code, so, se = None, b"", b""
    mock = holder = None
    hold_w = None
    try:
        if not exe:
            reqlog.touch()
            code, se = "missing-tool", b""
            return code
        if sc.get("no_mock"):
            reqlog.touch()
            holder = with_port(hold_port, a.port, a.port_wait, log)
            port = holder.getsockname()[1]
        else:
            cfg = json.loads((sdir / "config.json").read_text(encoding="utf-8"))
            mock = with_port(lambda p: MockServer(cfg, reqlog, p), a.port, a.port_wait, log).start()
            port = mock.port
        origin = "http://127.0.0.1:%d" % port
        (rdir / "origin").write_text(origin)
        env = tool_env(origin, port, sc.get("env", {}))
        timeout = sc.get("timeout", 30) * a.timeout_mult
        args = [x.encode("utf-8") for x in sc["argv"]]  # whatever the locale
        if a.wrapper:
            argv, exe = shlex.split(a.wrapper) + [exe] + args, None
            (rdir / "argv0").write_text(argv[len(argv) - len(args) - 1])
        else:
            argv = [sc.get("argv0", sc["tool"]).encode("utf-8")] + args
        stdin_arg, stdout_arg = subprocess.PIPE, subprocess.PIPE
        if sc.get("stdin_hold"):
            stdin_arg, hold_w = os.pipe()
            stdin = None
        if sc.get("stdout_closed"):
            r, stdout_arg = os.pipe()
            os.close(r)
        try:
            p = subprocess.Popen(argv, executable=exe, cwd=work, env=env, stdin=stdin_arg,
                                 stdout=stdout_arg, stderr=subprocess.PIPE)
        finally:
            for fd in (stdin_arg, stdout_arg):
                if fd != subprocess.PIPE:
                    os.close(fd)
        sig = sc.get("signal")
        if sig:
            def killer():
                t_end = time.time() + timeout
                while time.time() < t_end and p.poll() is None:
                    if mock is not None and mock.count >= sig.get("after_requests", 0):
                        time.sleep(sig.get("delay", 0.3) *
                                   (1 if sig.get("after_requests", 0) else a.timeout_mult))
                        if p.poll() is None:
                            send_signals(p, sig)
                        return
                    time.sleep(0.02)
            threading.Thread(target=killer, daemon=True).start()
        try:
            so, se = p.communicate(stdin, timeout=timeout)
            code = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            so, se = p.communicate()
            code = "timeout"
        return code
    finally:
        if mock is not None:
            mock.stop()
        if holder is not None:
            holder.close()
        if hold_w is not None:
            os.close(hold_w)
        (rdir / "stdout").write_bytes(so or b"")
        (rdir / "stderr").write_bytes(se or b"")
        (rdir / "exit").write_text(str(code))
        (rdir / "time").write_text("%.1f" % (time.time() - t0))
        for g in sc.get("gen", []):  # can be huge; never reported as created
            (work / g["path"]).unlink(missing_ok=True)
        created = {}
        for f in sorted(work.rglob("*")):
            rel = f.relative_to(work)
            if f.is_file() and rel not in before:
                created[rel.as_posix()] = blob(f.read_bytes())
        (rdir / "files.json").write_text(json.dumps(created, indent=1, sort_keys=True) + "\n",
                                         encoding="utf-8")


def parse_tools(a, err):
    tools = {}
    if a.bindir:
        for n in TOOLS + [PROBE]:
            p = a.bindir / n
            if p.is_file() and os.access(p, os.X_OK):
                tools[n] = str(p.resolve())
    for spec in a.tool:
        name, sep, path = spec.partition("=")
        if not sep or name not in TOOLS + [PROBE]:
            err("--tool expects NAME=PATH with NAME one of %s, got %r" % (" ".join(TOOLS + [PROBE]), spec))
        tools[name] = path
    if a.probe:
        tools[PROBE] = a.probe
    for name, path in tools.items():
        if not (os.path.isfile(path) and os.access(path, os.X_OK)):
            err("%s: %s is not an executable file" % (name, path))
        tools[name] = os.path.abspath(path)
    return tools


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="\n".join(__doc__.split("\n")[1:]))
    ap.add_argument("--workdir", type=Path, required=True,
                    help="scratch directory; its scenarios/ and results/ are recreated")
    ap.add_argument("--bindir", type=Path, help="directory holding the 8 tools and vtprobe")
    ap.add_argument("--tool", action="append", default=[], metavar="NAME=PATH",
                    help="path of one tool (repeatable; overrides --bindir)")
    ap.add_argument("--probe", metavar="PATH", help="path of vtprobe (same as --tool vtprobe=PATH)")
    ap.add_argument("--only", nargs="+", metavar="ID", help="run only these scenarios")
    ap.add_argument("--list", action="store_true", help="list the scenarios and exit")
    ap.add_argument("--jobs", "-j", type=int, default=1, help="scenarios run in parallel (default 1)")
    ap.add_argument("--port", type=int, default=0,
                    help="fixed mock port instead of a free one per scenario (implies --jobs 1)")
    ap.add_argument("--port-wait", type=int, default=600, metavar="SECONDS",
                    help="how long to wait for a busy --port (default 600)")
    ap.add_argument("--timeout-mult", type=float, default=1.0,
                    help="scale every scenario timeout (slow sanitizer builds)")
    ap.add_argument("--wrapper", metavar="CMD",
                    help="run every tool under this command, e.g. 'valgrind -q --error-exitcode=99'")
    ap.add_argument("--wrapper-exit", type=int, metavar="N",
                    help="fail a scenario whose tool exits with status N (the wrapper's error status)")
    ap.add_argument("--update-golden", action="store_true",
                    help="write each run's stdout to tests/wire/golden/<id>.stdout")
    ap.add_argument("-q", "--quiet", action="store_true", help="print failing scenarios only")
    a = ap.parse_args()
    sys.stdout.reconfigure(errors="backslashreplace")  # diffs on an ASCII terminal

    def err(msg):
        ap.error(msg)
    tools = parse_tools(a, err)
    if a.port:
        a.jobs = 1

    t_start = time.time()
    scen_root = a.workdir.resolve() / "scenarios"
    res_root = a.workdir.resolve() / "results"
    ids = gen_scenarios.write_all(scen_root)
    if a.list:
        for i in ids:
            sc = gen_scenarios.SC[i]
            print("%-40s %-14s %s" % (i, sc["tool"], sc["note"] or ""))
        return 0
    if a.only:
        unknown = sorted(set(a.only) - set(ids))
        if unknown:
            err("unknown scenario id(s): " + " ".join(unknown))
        ids = [i for i in ids if i in a.only]
    if res_root.exists():
        shutil.rmtree(res_root)
    res_root.mkdir(parents=True)

    lock = threading.Lock()

    def log(msg):
        with lock:
            print(msg, flush=True)

    missing = sorted({gen_scenarios.SC[i]["tool"] for i in ids} - set(tools))
    if missing:
        log("warning: no executable given for %s; their scenarios will FAIL" % " ".join(missing))

    fails = []

    def one(i):
        try:
            run_one(scen_root / i, res_root / i, tools, a, log)
        except Exception as e:  # PortBusy, unwritable workdir, ...
            (res_root / i).mkdir(parents=True, exist_ok=True)
            (res_root / i / "exit").write_text("runner-error: %s: %s" % (type(e).__name__, e))
        if a.update_golden and (res_root / i / "exit").read_text().strip().lstrip("-").isdigit():
            out = check.result_stdout(scen_root / i, res_root / i)
            (gen_scenarios.GOLDEN / (i + ".stdout")).write_bytes(out)
            (scen_root / i / "stdout").write_bytes(out)
        ok, status, lines = check.check_one(scen_root / i, res_root / i)
        if a.wrapper_exit is not None:
            code = (res_root / i / "exit").read_text().strip()
            if code == str(a.wrapper_exit):
                ok = False
                lines = lines + ["    wrapper reported errors (exit %s), see %s" % (
                    code, res_root / i / "stderr")]
        with lock:
            if not ok:
                fails.append((i, status, lines))
            if not a.quiet or not ok:
                print("%s %s %s" % ("ok  " if ok else "FAIL", i, status), flush=True)

    if a.jobs <= 1:
        for i in ids:
            one(i)
    else:
        ex = concurrent.futures.ThreadPoolExecutor(a.jobs)
        try:
            for f in [ex.submit(one, i) for i in ids]:
                f.result()
        except KeyboardInterrupt:  # do not start the queued scenarios
            ex.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            ex.shutdown(wait=True)
    fails.sort()
    check.report(fails, len(ids))
    print("wall time %.1fs; results in %s" % (time.time() - t_start, res_root))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
