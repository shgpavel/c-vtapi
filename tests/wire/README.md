# Wire-level regression suite

Runs the 8 CLI tools (`scan search ip domain_report url comments file_dist
url_dist`) and the library driver `vtprobe` through 218 scenarios, each
against a recording mock of the VirusTotal v2 API, and checks what went over
the wire against a model of the correct behaviour:

* **requests**, in order: method, path, decoded query pairs, request headers
  (all but Host and the framing ones, so `Accept: */*` and no `User-Agent`
  or `Expect`), content type, form pairs, multipart parts with name,
  filename, Content-Type and content (length + SHA-256).  Query pairs and
  multipart parts are compared in order too; only chunked encoding is
  ignored.  The mock keeps connections alive like a real server and records
  which connection each request came on; a scenario's `conns` pins which
  requests share one.
* **files** the tool creates in its working directory (names, length +
  SHA-256), e.g. `scan --download --out`.
* the **exit status** (`exit`, default 0; -N means killed by signal N).
* **stdout**, against `golden/<id>.stdout`, after dropping the
  nondeterministic `progress_callback N/M` lines of `scan` and writing the
  mock's `http://127.0.0.1:<port>` as `{MOCK}`.
* stderr is not compared, but a sanitizer report in it (AddressSanitizer,
  LeakSanitizer, UndefinedBehaviorSanitizer) fails the scenario, so an
  ASan build catches leaks and errors that happen after the last request.
* a missing tool or a tool that times out fails the scenario.

A mismatch prints a unified diff of expected vs recorded requests, files or
stdout and makes the run exit 1.

| file | role |
|---|---|
| `gen_scenarios.py` | the scenario table and the model (source of truth) |
| `golden/` | the expected stdout of every scenario |
| `run.py` | generates the scenarios into the work dir, runs them, checks them |
| `check.py` | the checker (also usable alone on an existing work dir) |
| `mockvt.py` | recording mock HTTP server (response config format in its docstring) |
| `gen_util.py` | deterministic generated inputs (64 MiB uploads etc.), blob hashing |

## Running

`meson test --suite wire` runs it on the build tree.  Standalone:

```sh
python3 tests/wire/run.py --workdir /tmp/wire --bindir builddir \
    --probe builddir/tests/vtprobe                                 # tools from the meson build dir
python3 tests/wire/run.py --workdir /tmp/wire \
    --tool scan=builddir/scan --tool ip=builddir/ip ... --probe builddir/tests/vtprobe
python3 tests/wire/run.py ... --only ip_long search_pagination    # a subset
python3 tests/wire/run.py ... --list                              # ids, tools, notes
python3 tests/wire/run.py ... --timeout-mult 10 -j 4 \
    --wrapper 'valgrind -q --error-exitcode=99 --leak-check=full' --wrapper-exit 99
python3 tests/wire/check.py --scenarios /tmp/wire/scenarios --results /tmp/wire/results
```

`--wrapper CMD` runs every tool under CMD (argv[0] then becomes the tool's
path, which the stdout comparison maps back); `--wrapper-exit N` fails a
scenario whose tool exits with N, i.e. the wrapper's error status.  The
tools run with `TZ=XYZ-5:30` (not UTC), and the harness passes argv and
reads and writes its files as UTF-8 whatever the locale.

The whole suite takes about 35 s (`-j 4`: about 15 s); Ctrl-C stops a
parallel run after the scenarios in flight.  Everything a scenario did is
kept in `WORKDIR/results/<id>/` (`requests.jsonl`, `files.json`, `stdout`,
`stderr`, `exit`, `cwd/`).

**Ports.**  Each scenario gets its own mock on a kernel-chosen free port
(bind to port 0), and the tool gets
`VT_API_BASE_URL=http://127.0.0.1:<port>/vtapi/v2/`, so the suite can run
concurrently with itself and anything else.  Mock response bodies and
headers may say `{MOCK}` (replaced by `http://127.0.0.1:<port>`), scenario
`env` values `{MOCK}` or `{PORT}`.  Connection-refused scenarios get a port
that is bound but not listening.  `--port N` pins every mock to port N
(for an old build with a compiled-in base URL; waits while N is busy).

## Adding a scenario

Add one `add(...)` call to `gen_scenarios.py` next to its peers, then run
the suite with `--update-golden` (add `--only ID`) to write its
`golden/<id>.stdout`, and check that file by hand before committing it:

```python
add("ip_report_ok", "ip", ["--apikey", K, "--report", "1.2.3.4"],   # id, tool, argv
    {R("GET", IP): [J({"response_code": 1, "verbose_msg": "ok"})]},  # mock responses, in order
    [GET(IP, ("apikey", K), ("ip", "1.2.3.4"))],                     # model: expected requests
    note="why the model looks like this (optional)",
    files={"o.bin": blob(b"DATA")},                                  # files the tool must create
    inputs={"hello.txt": b"hi\n"},                                   # copied to cwd/inputs/
    exit=0, conns=[0])                                              # exit status, connection labels
```

Helpers: `J` / `T` / `BIN` / `DROP` build responses (`status=`, `delay=`,
`chunks=`, `headers=`, `close=`), `GET` / `MP` / `P` / `F` build expected
requests and multipart parts.  Further keys (`stdin`, `stdin_hold`,
`stdout_closed`, `gen`, `env`, `signal`, `no_mock`, `inputs_at_cwd`,
`timeout`) are documented in `run.py`.  A `DROP` that follows a response
on a kept connection makes libcurl re-send a GET once (`ip_drop_stale`);
give that response `close=True` when the scenario models a single failed
request.  The model is what a
correct implementation sends, not what the current code happens to send;
`Dn` notes name the behaviour decisions of the 1.0 redesign (e.g. D9: a
search response offset of `""` means there is no next page).
