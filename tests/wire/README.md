# Wire-level regression suite

Runs the 8 CLI tools (`scan search ip domain_report url comments file_dist
url_dist`) and the library driver `vtprobe` through 206 scenarios, each
against a recording mock of the VirusTotal v2 API, and checks what went over
the wire against a model of the correct behaviour:

* **requests**, in order: method, path, decoded query pairs, content type,
  form pairs, multipart part names / filenames / content (length + SHA-256).
  The order of query pairs and multipart parts does not matter; request
  headers and chunked encoding are ignored.
* **files** the tool creates in its working directory (names, length +
  SHA-256), e.g. `scan --download --out`.
* a missing tool or a tool that times out fails the scenario.  Stdout and
  exit status are not checked (the exit status is shown for information).

A mismatch prints a unified diff of expected vs recorded requests/files and
makes the run exit 1.

| file | role |
|---|---|
| `gen_scenarios.py` | the scenario table and the model (source of truth) |
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
path, which only stdout would show); `--wrapper-exit N` fails a scenario
whose tool exits with N, i.e. the wrapper's error status.

The whole suite takes about 35 s (`-j 4`: about 15 s).  Everything a
scenario did is kept in `WORKDIR/results/<id>/` (`requests.jsonl`,
`files.json`, `stdout`, `stderr`, `exit`, `cwd/`).

**Ports.**  Each scenario gets its own mock on a kernel-chosen free port
(bind to port 0), and the tool gets
`VT_API_BASE_URL=http://127.0.0.1:<port>/vtapi/v2/`, so the suite can run
concurrently with itself and anything else.  Mock response bodies and
headers may say `{MOCK}` (replaced by `http://127.0.0.1:<port>`), scenario
`env` values `{MOCK}` or `{PORT}`.  Connection-refused scenarios get a port
that is bound but not listening.  `--port N` pins every mock to port N
(for an old build with a compiled-in base URL; waits while N is busy).

## Adding a scenario

Add one `add(...)` call to `gen_scenarios.py` next to its peers:

```python
add("ip_report_ok", "ip", ["--apikey", K, "--report", "1.2.3.4"],   # id, tool, argv
    {R("GET", IP): [J({"response_code": 1, "verbose_msg": "ok"})]},  # mock responses, in order
    [GET(IP, ("apikey", K), ("ip", "1.2.3.4"))],                     # model: expected requests
    note="why the model looks like this (optional)",
    files={"o.bin": blob(b"DATA")},                                  # files the tool must create
    inputs={"hello.txt": b"hi\n"})                                   # copied to cwd/inputs/
```

Helpers: `J` / `T` / `BIN` / `DROP` build responses (`status=`, `delay=`,
`chunks=`, `headers=`), `GET` / `MP` / `P` / `F` build expected requests and
multipart parts.  Further keys (`stdin`, `gen`, `env`, `signal`, `no_mock`,
`inputs_at_cwd`, `timeout`) are documented in `run.py`.  The model is what a
correct implementation sends, not what the current code happens to send;
`Dn` notes name the behaviour decisions of the 1.0 redesign (e.g. D9: a
search response offset of `""` means there is no next page).
