# c-vtapi

A small C client library for the VirusTotal v2 API (public and private
endpoints), plus eight command-line tools built on it.

* One public header, `<vt/vt.h>`, and one library, `libcvtapi`.
* Built on [libcurl](https://curl.se/libcurl/) (HTTP, TLS, multipart
  uploads) and [jansson](https://github.com/akheron/jansson). Responses are
  returned as plain jansson `json_t` values.
* The library is written in C23 for POSIX systems (it needs pthreads). The
  header is self-contained and can be used from C99 or later and from C++.
* Synchronous and blocking. One opaque `vt_client` holds the API key, the
  base URL, a reusable libcurl handle and the result of the last operation.

## Contents

- [Building and installing](#building-and-installing)
- [Quick start](#quick-start)
- [API conventions](#api-conventions)
- [Function reference](#function-reference)
- [Command-line tools](#command-line-tools)
- [Testing](#testing)
- [Changes from the legacy VtXxx API](#changes-from-the-legacy-vtxxx-api)
- [License](#license)

## Building and installing

Requirements:

| What | Version |
|---|---|
| C compiler with C23 (`-std=c23`, or `-std=c2x` as a fallback) | tested with GCC 13.3, GCC 14.2 and Clang 18.1 |
| meson and ninja | meson 1.4.0 or newer (`pip install meson` if your distribution ships an older one) |
| libcurl (development package) | 7.85.0 or newer |
| jansson (development package) | 2.14 or newer |
| pkg-config | any |
| python3 | only for the wire test suite |

On Debian or Ubuntu: `apt install ninja-build pkg-config libcurl4-openssl-dev libjansson-dev`,
plus meson from your distribution or from pip.

```sh
meson setup build                  # add -Dtests=false to skip vtprobe and the tests
meson compile -C build
meson test -C build                # see "Testing"
meson install -C build             # or: meson install -C build --destdir "$PWD/stage"
```

By default this builds and installs a static library. Pass
`-Ddefault_library=shared` (or `both`) to `meson setup` for `libcvtapi.so.1`.
The build uses `warning_level=3` and `werror=true`, plus a list of extra
warnings.

`meson install` installs:

| File | Purpose |
|---|---|
| `include/vt/vt.h` | the only public header |
| `lib/.../libcvtapi.a` (or `libcvtapi.so*` for a shared build) | the library |
| `lib/.../pkgconfig/cvtapi.pc` | pkg-config module `cvtapi` |

The command-line tools are not installed (see [Command-line tools](#command-line-tools)).

Building an application against the installed library:

```sh
cc -o report report.c $(pkg-config --cflags --libs cvtapi)
```

The pkg-config module pulls in jansson, libcurl and `-pthread`. As a meson
subproject, use `dependency('cvtapi')`: the project overrides that
dependency name.

## Quick start

This program looks up the report for a hash and prints the detection ratio.

```c
/* report.c - print the detection ratio of a file hash */
#include <stdio.h>
#include <stdlib.h>

#include <vt/vt.h>

int main(int argc, char **argv)
{
	vt_client *c;
	json_t *report = NULL;
	vt_err e;
	int code;

	if (argc != 3) {
		fprintf(stderr, "usage: %s APIKEY HASH\n", argv[0]);
		return 2;
	}

	/* NULL or "" selects https://www.virustotal.com/vtapi/v2/ */
	c = vt_client_new(argv[1], getenv("VT_API_BASE_URL"));
	if (!c) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	e = vt_file_report(c, argv[2], &report);
	if (e != VT_OK) {
		/* report is NULL here; json_decref(NULL) would be harmless */
		fprintf(stderr, "file/report: %s: %s (HTTP %ld, curl %d)\n",
		        vt_strerror(e), vt_errmsg(c), vt_http_status(c),
		        vt_curl_code(c));
		vt_client_free(c);
		return 1;
	}

	/* report is a new reference that we own */
	if (vt_response_code(report, &code) && code == 1) {
		printf("%s: %lld/%lld\n", argv[2],
		       (long long)json_integer_value(
		           json_object_get(report, "positives")),
		       (long long)json_integer_value(
		           json_object_get(report, "total")));
	} else {
		const char *msg = vt_verbose_msg(report); /* borrowed */
		printf("%s: %s\n", argv[2], msg ? msg : "no report");
	}

	json_decref(report);
	vt_client_free(c);
	return 0;
}
```

Possible output:

```
$ ./report "$VT_KEY" 44d88612fea8a8f36de82e1278abb02f
44d88612fea8a8f36de82e1278abb02f: 3/70
$ ./report bad-key 44d88612fea8a8f36de82e1278abb02f
file/report: unexpected HTTP status: HTTP 403 (HTTP 403, curl 0)
```

## API conventions

These rules apply to every function unless its comment in `vt/vt.h` says
otherwise. The header is the full reference; this section is the overview.

**Errors.** Every operation returns a `vt_err`. `VT_OK` (0) means success;
any other value is a failure. After every operation the client also
describes its result: `vt_http_status(c)` is the final HTTP status (0 if no
response arrived), `vt_curl_code(c)` is the libcurl `CURLcode` (0 if none),
and `vt_errmsg(c)` is a human-readable message such as
`Couldn't connect to server`, `HTTP 403` or `JSON parse error: ...`.
`vt_strerror(e)` gives a fixed text for each code.

| Code | Meaning |
|---|---|
| `VT_OK` | success |
| `VT_EINVAL` | NULL client, missing required argument, client busy (called from inside one of its own transfer callbacks; the client's diagnostics are left untouched); nothing was sent |
| `VT_ENOMEM` | allocation failed, or a JSON response body exceeded 256 MiB |
| `VT_ECURL` | libcurl setup or transfer failure (connect, TLS, reset, write sink returned short, ...); see `vt_curl_code()` |
| `VT_EHTTP` | the HTTP status is not accepted by the endpoint; see `vt_http_status()` |
| `VT_EJSON` | the body is empty or is not a JSON object or array |
| `VT_EPROTO` | valid JSON that lacks what the operation needs (no `upload_url`, a malformed distribution element) |
| `VT_ECANCEL` | cancelled by `vt_cancel()` or by the progress callback (`vt_curl_code()` is 42) |
| `VT_EIO` | a local file to upload does not exist or is not readable (`vt_curl_code()` is 26). Anything else is streamed as read, so a directory uploads as an empty file and a read error partway through is not detected |

The `file/*` endpoints and the distribution feeds accept only HTTP 200, and
downloads accept 200 or 302. The `url/*`, `ip-address/*`, `domain/*`,
`comments/*` and `file/scan/upload_url` endpoints accept any status: an
error such as 403 with a JSON body is `VT_OK`, so check `vt_http_status()`
there.

Required pointer arguments must be non-NULL; a NULL one gives `VT_EINVAL`
and nothing is sent. Only the functions whose comment says so reject an
empty string (for example the path of `vt_file_scan()` or the query of
`vt_file_search()`); every other string, `""` included, is sent as given.

**Ownership.** Functions that take `json_t **out` store a new reference in
`*out` on success, and you release it with `json_decref()`. On any error
`*out` is set to NULL, so `json_decref(*out)` is always safe. Pass `out` as
NULL if you do not need the body: it is still parsed and checked, then
released. String arguments are only read during the call (copied when
kept). Returned `const char *` values are borrowed, either from the client
(valid until its next operation or `vt_client_free()`) or from a `json_t`
(valid while that value lives). The only results you must `free()` are
`*url` from `vt_file_upload_url()` and `*data` from `vt_file_download_mem()`.

**Threads.** A `vt_client` is not thread-safe: use each client from one
thread at a time. Different clients can be used concurrently, because the
library has no shared mutable state apart from the atomic debug level, and
libcurl runs with `CURLOPT_NOSIGNAL`. libcurl's global initialisation runs
once, under `pthread_once`, at the first `vt_client_new()` or
`vt_set_debug()` call. `vt_cancel()` is the one function that may be called
from any thread.

**Callbacks.** All callbacks run synchronously on the calling thread. The
progress callback and the download sink run inside the transfer: calling
another operation on the same client from them returns `VT_EINVAL` and
records nothing, so the client's diagnostics keep describing the running
operation. Distribution callbacks run after the transfer and may use the
client; the diagnostics read after the distribution call still describe
that call, not the nested ones. Everything a callback receives is borrowed
for the duration of the call. Treat the `json_t *item` as read-only, and
keep it with `json_incref()` or `json_deep_copy()` if you need it later.

**Cancellation and timeouts.** `vt_cancel(c)` asks the operation currently
running on `c` to stop. It fails with `VT_ECANCEL` at its next progress
tick, which also happens while connecting. A cancel applies to one
operation only. It is cleared when the next operation starts, so a cancel
issued while the client is idle has no effect. `vt_file_scan_big()` is two
requests but one operation: a cancel between them stops it before the
upload connects. `vt_cancel()` is a lock-free atomic store, safe from
another thread and from a signal handler. The library sets no timeouts. To
enforce one, return non-zero from the progress callback (installed with
`vt_client_set_progress()`), which aborts the operation with `VT_ECANCEL`.

**SIGPIPE.** The library installs no signal handlers and leaves `SIGPIPE`
alone. libcurl runs with `CURLOPT_NOSIGNAL` (needed so it never uses
`SIGALRM`), so instead of ignoring `SIGPIPE` around transfers it sends with
`MSG_NOSIGNAL` (Linux) or `SO_NOSIGPIPE` (BSD/macOS): a server closing the
connection does not raise it. Writes made by your own callbacks, such as a
download sink writing to a pipe, follow your process's `SIGPIPE` setting.

**Base URL.** `vt_client_new(apikey, base_url)` uses `base_url` verbatim as
the prefix of every endpoint path, so keep the trailing `/`, for example
`http://127.0.0.1:8765/vtapi/v2/`. NULL or `""` selects
`VT_DEFAULT_BASE_URL` (`https://www.virustotal.com/vtapi/v2/`). The library
does not read the environment for this. Pass `getenv("VT_API_BASE_URL")` if
you want the same override as the tools. The absolute upload URL returned
by `file/scan/upload_url` is used as is. Only `http` and `https` URLs are
followed, including on redirects (only `http` if libcurl was built without
TLS).

**Connections.** Each client keeps one libcurl handle for its whole life, so
connections, DNS results and TLS sessions are reused across operations.
Every request starts from reset options, so nothing one request sets leaks
into the next. The GET lookups share the kept connections, and libcurl
re-sends a GET once if a reused connection dies before any response byte.
Every POST (the scans, rescans, `file/report`, `file/search`, `url/scan`,
`url/report`, `comments/put` and the upload of `vt_file_scan_big()`) uses a
new connection that is closed afterwards, so a POST is never sent twice.

**Wire format.** Query-string values are percent-encoded like
`curl_easy_escape()`: `A-Z a-z 0-9 - . _ ~` are kept and every other byte
becomes `%XX`. Multipart values are sent verbatim. A client without an API
key sends an empty `apikey`.

**Debug output.** `vt_set_debug(level)` sets a process-wide level: 0 is
silent (the default), 1 or more prints request and error lines on stderr
and turns on `CURLOPT_VERBOSE`, and 2 or more also prints response bodies.
The initial level comes from the environment variable `VT_DEBUG`. It is read
once, when the first client is created or at the first `vt_set_debug()`
call, and `vt_set_debug()` always overrides it. Debug output can contain
the API key.

**Versioning.** `VT_VERSION_MAJOR`, `VT_VERSION_MINOR`, `VT_VERSION_PATCH`
and `VT_VERSION_NUM` (`0xMMmmpp`) describe the header, and `vt_version()`
returns the number of the library actually linked. The public structs
(`struct vt_rescan_opts`, `struct vt_dist_query`) are part of the ABI. New
members are only added together with a SONAME bump.

## Function reference

`c` is a `vt_client *`. Functions marked with † warn when their result is
ignored (`VT_NODISCARD`).

**Library and client**

| Function | Purpose |
|---|---|
| `vt_client *vt_client_new(const char *apikey, const char *base_url)` † | create a client (both strings are copied; NULL apikey is allowed); NULL on out-of-memory |
| `void vt_client_free(vt_client *c)` | destroy a client and close its connections (NULL is a no-op) |
| `vt_err vt_client_set_apikey(vt_client *c, const char *apikey)` † | replace the API key (NULL clears it) |
| `void vt_client_set_progress(vt_client *c, vt_progress_fn *fn, void *userdata)` | install or remove (`fn` NULL) the progress callback for all later operations |
| `void vt_cancel(vt_client *c)` | cancel the running operation (any thread, signal-safe) |
| `long vt_http_status(const vt_client *c)` | HTTP status of the last operation |
| `int vt_curl_code(const vt_client *c)` | `CURLcode` of the last operation |
| `const char *vt_errmsg(const vt_client *c)` | message for the last operation (never NULL, borrowed) |
| `const char *vt_strerror(vt_err err)` | fixed text for an error code |
| `void vt_set_debug(int level)` | process-wide debug level |
| `unsigned vt_version(void)` | `VT_VERSION_NUM` of the linked library |

**Helpers for returned JSON** (NULL-safe, results are borrowed)

| Function | Purpose |
|---|---|
| `bool vt_response_code(const json_t *resp, int *code)` | top-level `response_code` (false if absent) |
| `const char *vt_verbose_msg(const json_t *resp)` | top-level `verbose_msg` if it is a non-empty string, else NULL |
| `const char *vt_next_offset(const json_t *resp)` | `offset` of a search page if it is a non-empty string (the next page's cursor), else NULL |

**file/**

| Function | Request | Notes |
|---|---|---|
| `vt_file_scan(c, path, notify_url, &out)` † | POST `file/scan` | uploads the file at `path`; `notify_url` is sent if non-empty; files of 32 MiB and more should use `vt_file_scan_big()` |
| `vt_file_scan_mem(c, filename, data, len, notify_url, &out)` † | POST `file/scan` | uploads `len` bytes from memory as `filename`; `len` must be below 32 MiB |
| `vt_file_scan_big(c, path, &out)` † | GET `file/scan/upload_url`, then POST to that URL | large files; one operation for cancellation |
| `vt_file_upload_url(c, &url)` † | GET `file/scan/upload_url` | `*url` is malloc'd, `free()` it |
| `vt_file_rescan(c, resource, &opts, &out)` † | POST `file/rescan` | `resource` is a hash or a comma-separated list; `opts` (may be NULL) is a `struct vt_rescan_opts` with `date`, `period`, `repeat`, `notify_url`, `notify_changes_only` |
| `vt_file_rescan_delete(c, resource, &out)` † | POST `file/rescan/delete` | |
| `vt_file_report(c, resource, &out)` † | POST `file/report` | |
| `vt_file_search(c, query, offset, &out)` † | POST `file/search` | one page; pass `vt_next_offset(out)` as `offset` for the next one; hashes are in `"hashes"` |
| `vt_file_clusters(c, date, &out)` † | GET `file/clusters` | `date` is `YYYY-MM-DD`; clusters are in `"clusters"` |
| `vt_file_download(c, hash, fn, userdata)` † | GET `file/download` | streams the body to a `vt_write_fn` sink; follows redirects |
| `vt_file_download_fp(c, hash, fp)` † | GET `file/download` | writes to a stream you opened (not closed) |
| `vt_file_download_mem(c, hash, &data, &len)` † | GET `file/download` | `*data` is malloc'd (NUL-terminated, not counted in `*len`), `free()` it |

**url/, ip-address/, domain/, comments/**

| Function | Request | Notes |
|---|---|---|
| `vt_url_scan(c, url, &out)` † | POST `url/scan` | `url` may hold several newline-separated URLs |
| `vt_url_report(c, resource, flags, &out)` † | POST `url/report` | `flags`: `VT_URL_REPORT_SCAN` sends `scan=1`, `VT_URL_REPORT_ALL_INFO` sends `all_info=1` |
| `vt_ip_report(c, ip, &out)` † | GET `ip-address/report` | |
| `vt_domain_report(c, domain, &out)` † | GET `domain/report` | |
| `vt_comments_put(c, resource, comment, &out)` † | POST `comments/put` | |
| `vt_comments_get(c, resource, before, &out)` † | GET `comments/get` | `before` (may be NULL) is the datetime token for paging; needs an API key |

**file/distribution, url/distribution** (private API feeds)

| Function | Request | Notes |
|---|---|---|
| `vt_file_distribution(c, &q, fn, userdata, &out)` † | GET `file/distribution` | calls `fn` (a `vt_file_dist_fn`) for each element and advances `q.after` |
| `vt_url_distribution(c, &q, fn, userdata, &out)` † | GET `url/distribution` | the same with a `vt_url_dist_fn` |

`struct vt_dist_query` holds `before`, `after`, `limit` and `reports`. Each
member is sent only when non-zero, and `reports` sends `reports=true` for
files and `allinfo=true` for URLs. After each valid element `q.after` is
set to its timestamp, so calling again with the same struct fetches the
next page:

```c
static void on_file(const char *link, long long timestamp, const char *sha256,
                    const char *name, json_t *item, void *userdata)
{
	printf("%lld %s %s\n", timestamp, sha256, name ? name : "(no name)");
}

struct vt_dist_query q = {.limit = 100};
for (int page = 0; page < 3; page++)
	if (vt_file_distribution(c, &q, on_file, NULL, NULL))
		break;
```

Search paging works the same way, except that you carry the cursor
yourself:

```c
char *offset = NULL; /* first page */
vt_err e;
do {
	json_t *page, *h;
	size_t i;

	e = vt_file_search(c, "type:peexe positives:5+", offset, &page);
	free(offset);
	offset = NULL;
	if (e)
		break;
	json_array_foreach(json_object_get(page, "hashes"), i, h)
		if (json_is_string(h))
			puts(json_string_value(h));
	if (vt_next_offset(page)) /* borrowed from page: copy it */
		offset = strdup(vt_next_offset(page));
	json_decref(page);
} while (offset);
```

## Command-line tools

`meson compile` also builds eight small tools in the build directory. They
are examples and test drivers, and they are not installed, because names
such as `ip` and `url` would shadow system commands. Their command-line
interface is unchanged from earlier releases.

Common behaviour:

* Options are parsed with `getopt_long_only()`, so `-name` equals `--name`,
  unique prefixes work and `--opt=value` is accepted.
* `scan`, `ip`, `domain_report` and `url` act on each option as it is
  parsed, from left to right, so give `--apikey` first: an action that
  needs a key before one was given prints `Must set --apikey first` and
  exits with status 1. `search`, `comments`, `file_dist` and `url_dist` act
  after all options are parsed, so their order does not matter, and never
  print that message: without `--apikey` they send an empty key, except
  that the comments fetch prints `Error: -1` and sends nothing. The
  exception is `comments --put`, which runs as soon as it is parsed: give
  `--apikey` and `--resource` before it.
* Without arguments a tool prints its usage and exits 0. `--help` prints
  the usage too. `--verbose[=X]` only echoes itself (use `VT_DEBUG` for
  debug output). Options that a tool accepts but does not handle
  (`comments --get`, `--before` and `--after` of `file_dist` and
  `url_dist`) print `?? getopt returned character code 0NNN ??` on stdout,
  as do unrecognized options (code 077, after getopt's message on stderr).
* Results are printed as `Response:` followed by the JSON indented by four
  spaces. A failure prints `Error: N` (`search`, `file_dist` and `url_dist`
  print `returned error N`), where N is the HTTP status for a rejected
  status, the libcurl error code for a transfer failure (42 means
  cancelled, 26 means an unreadable upload file) or -1 for anything else.
* The exit status is 0, including after a failed request. It is 1 only for
  a missing required option or out of memory. As in earlier releases, a
  tool writing to a pipe whose reader has exited dies of `SIGPIPE`, so
  `file_dist --repeat -1 | head` stops.
* Environment: `VT_API_BASE_URL`, if set and non-empty, replaces
  `https://www.virustotal.com/vtapi/v2/` (keep the trailing `/`).
  `VT_DEBUG=1` or `2` turns on the library's debug output on stderr.

| Tool | Options | What it does |
|---|---|---|
| `scan` | `--apikey KEY`, `--filescan FILE` (repeatable), `--scaninput[=NAME]`, `--rescan HASH`, `--report HASH`, `--clusters YYYY-MM-DD`, `--out FILE`, `--download HASH` | `--filescan` uploads a file, and files of 64 MiB and more go through the large-file upload URL. `--scaninput` uploads stdin, named NAME (default `filename`). The input must be smaller than 32 MiB (33554432 bytes): larger input prints `read 33554432 bytes` and `Error: -1` and sends nothing (it is not truncated), and empty input prints `ERROR 0` and `Error: -1`. `--report` also prints `Msg:` and `response code:`. `--download` saves to the file given by an earlier `--out`. SIGHUP or SIGTERM cancels the running transfer and every later one. |
| `search` | `--apikey KEY`, `--query Q`, `--offset X`, `--repeat N` | runs N (default 1) searches, each continuing at the offset the previous page returned, and prints the hashes. After a page without a non-empty `offset`, the next search starts again from the first page. |
| `ip` | `--apikey KEY`, `--report IP` | IP address report |
| `domain_report` | `--apikey KEY`, `--report DOMAIN` | domain report |
| `url` | `--apikey KEY`, `--report-scan`, `--all-info`, `--scan URL`, `--report URL` | `--scan` submits a URL. `--report` fetches a report, adding `scan=1` or `all_info=1` if `--report-scan` or `--all-info` came before it. |
| `comments` | `--apikey KEY`, `--resource HASH`, `--before TOKEN`, `--put "TEXT"`, `--get` | fetches the comments of the resource after the options are parsed, unless `--put` was given or there are non-option arguments. `--put` posts a comment (the result is not printed). `--get` has no effect besides the `??` line. |
| `file_dist` | `--apikey KEY`, `--reports 0\|1`, `--limit N`, `--repeat N`, `--sleep S` | fetches N (default 3) pages of the file feed, S (default 3) seconds apart, each continuing after the last timestamp, and stops at the first error |
| `url_dist` | `--apikey KEY`, `--allinfo 0\|1`, `--limit N`, `--repeat N`, `--sleep S` | the same for the URL feed |

`file_dist` and `url_dist` accept `--before` and `--after` but do not
implement them. Their usage texts advertise `--all-info`, which neither
tool recognizes: the real options are `--reports N` (`file_dist`) and
`--allinfo N` (`url_dist`). Examples:

```sh
export VT_KEY=...
build/scan --apikey "$VT_KEY" --filescan /bin/ls --report 44d88612fea8a8f36de82e1278abb02f
cat sample.bin | build/scan --apikey "$VT_KEY" --scaninput=sample.bin
build/scan --apikey "$VT_KEY" --out sample.bin --download 44d88612fea8a8f36de82e1278abb02f
build/url --apikey "$VT_KEY" --all-info --report http://example.com/
build/search --apikey "$VT_KEY" --query 'type:peexe positives:5+' --repeat 3
build/url_dist --apikey "$VT_KEY" --allinfo 1 --repeat 1
VT_API_BASE_URL=http://127.0.0.1:8765/vtapi/v2/ VT_DEBUG=1 build/ip --apikey KEY --report 8.8.8.8
```

## Testing

`meson test -C build` runs two tests, and neither needs network access
beyond loopback:

* **unit** (`tests/unit.c`) checks the parts of the public API that need no
  server: error strings, the version, the JSON helpers and argument
  validation. A rejected call must not start a transfer and must reset
  `*out`.
* **wire** (`tests/wire/`, needs python3) runs the eight tools and
  `vtprobe` through about 220 scenarios. `vtprobe` is a small driver for
  library behaviour that the tools cannot reach. Each scenario gets its
  own recording mock server on a free loopback port, and the suite checks
  every request sent (method, path, query, headers, multipart parts and
  their bytes, and which requests share a connection), every file
  created, the exit status and stdout against a model of the correct
  behaviour and golden files. A sanitizer report on stderr fails a
  scenario too, so the sanitizer build below also catches leaks. A
  mismatch prints a diff. See `tests/wire/README.md` for running single
  scenarios and adding new ones.

```sh
meson test -C build --suite wire --print-errorlogs   # only the wire suite
meson setup build-asan -Db_sanitize=address,undefined && meson test -C build-asan
python3 tests/wire/run.py --workdir /tmp/wire --bindir build --probe build/tests/vtprobe \
    --wrapper 'valgrind -q --error-exitcode=99 --leak-check=full' --wrapper-exit 99 \
    --timeout-mult 10 -j 4
```

With Clang, also pass `-Db_lundef=false`; this needs Clang's sanitizer
runtime (for example Ubuntu's `libclang-rt-18-dev`).

## Changes from the legacy VtXxx API

Version 1.0 replaces the reference-counted `VtXxx` objects (one object type
per endpoint, a `VtResponse` per result) with a single client and plain
jansson values. Include `<vt/vt.h>` instead of the `VtXxx.h` headers, link
with `pkg-config cvtapi`, and create one `vt_client` where you used to
create one object per endpoint. Results come back through `json_t **out`.
The old object holding the "last response" is gone.

### Function mapping

`T` stands for any of `VtFile`, `VtUrl`, `VtIpAddr`, `VtDomain`,
`VtComments`, `VtFileDist` and `VtUrlDist`.

| Legacy | Replacement |
|---|---|
| `T_new()` | `vt_client_new(apikey, base_url)`: one client for all endpoints |
| `T_put(&obj)` | `vt_client_free(c)` |
| `T_get(obj)` | none: a client has a single owner |
| `T_setApiKey(obj, key)` | `vt_client_set_apikey(c, key)`, or the `apikey` argument of `vt_client_new()` |
| `T_getResponse(obj)` | the `json_t **out` argument of each operation |
| `VtDebug_setDebugLevel(level)` | `vt_set_debug(level)`, or the `VT_DEBUG` environment variable |
| `VtResponse_new`, `VtResponse_get`, `VtResponse_put` | `json_t` reference counting: `json_incref()`, `json_decref()` |
| `VtResponse_getJanssonObj(r)` | the `json_t *` itself |
| `VtResponse_toJSONstr(r, VT_JSON_FLAG_INDENT)` | `json_dumps(j, JSON_INDENT(4))` (free the result) |
| `VtResponse_fromJSONstr(r, s)` | `json_loads(s, 0, &err)` |
| `VtResponse_getResponseCode(r, &code)` | `vt_response_code(j, &code)` (returns `bool`) |
| `VtResponse_getVerboseMsg(r, buf, size)` | `vt_verbose_msg(j)` (borrowed, no copy) |
| `VtResponse_getIntValue(r, key, &v)` | `json_integer_value(json_object_get(j, key))` |
| `VtResponse_getString(r, key)` | `json_string_value(json_object_get(j, key))` (borrowed; `strdup()` it to keep it) |
| `VtFile_scan(f, path, notify_url)` | `vt_file_scan(c, path, notify_url, &out)` |
| `VtFile_scanMemBuf(f, filename, buf, len, notify_url)` | `vt_file_scan_mem(c, filename, buf, len, notify_url, &out)` |
| `VtFile_scanBigFile(f, path)` | `vt_file_scan_big(c, path, &out)` |
| `VtFile_uploadUrl(f, &url)` | `vt_file_upload_url(c, &url)` |
| `VtFile_rescanHash(f, hash, date, period, repeat, notify_url, changes_only)` | `vt_file_rescan(c, hash, &(struct vt_rescan_opts){...}, &out)`; `date` is now an `int64_t` of Unix seconds |
| `VtFile_rescanDelete(f, hash)` | `vt_file_rescan_delete(c, hash, &out)` |
| `VtFile_report(f, resource)` | `vt_file_report(c, resource, &out)` |
| `VtFile_setOffset(f, offset)` + `VtFile_search(f, query, cb, data)` | `vt_file_search(c, query, offset, &out)`; iterate `"hashes"` yourself and get the next cursor from `vt_next_offset(out)` |
| `VtFile_clusters(f, date, cb, data)` | `vt_file_clusters(c, date, &out)`; iterate `"clusters"` yourself |
| `VtFile_download(f, hash, cb, data)` | `vt_file_download(c, hash, fn, userdata)`; the sink is now `size_t fn(const void *data, size_t len, void *userdata)` |
| `VtFile_downloadToFile(f, hash, path)` | open the file yourself and call `vt_file_download_fp(c, hash, fp)`, or use `vt_file_download_mem()` |
| `VtFile_setProgressCallback(f, cb, data)` | `vt_client_set_progress(c, fn, userdata)`; the callback receives the byte counters and returns non-zero to cancel |
| `VtFile_getProgress(f, ...)` | the arguments of the progress callback |
| `VtFile_cancelOperation(f)` | `vt_cancel(c)` (now for any operation, not only `VtFile` ones) |
| `VtUrl_scan(u, url)` | `vt_url_scan(c, url, &out)` |
| `VtUrl_report(u, url, scan, all_info)` | `vt_url_report(c, url, flags, &out)` with `VT_URL_REPORT_SCAN` and `VT_URL_REPORT_ALL_INFO` |
| `VtIpAddr_report(o, ip)` | `vt_ip_report(c, ip, &out)` |
| `VtDomain_report(o, domain)` | `vt_domain_report(c, domain, &out)` |
| `VtComments_setResource(o, r)` + `VtComments_add(o, comment)` | `vt_comments_put(c, r, comment, &out)` |
| `VtComments_setResource(o, r)` + `VtComments_setBefore(o, b)` + `VtComments_retrieve(o)` | `vt_comments_get(c, r, b, &out)` (`b` may be NULL) |
| `VtFileDist_setBefore`, `VtFileDist_setAfter`, `VtFileDist_setLimit`, `VtFileDist_setReports` | the `before`, `after`, `limit` and `reports` members of `struct vt_dist_query` |
| `VtFileDist_getDistribution(o)` | `vt_file_distribution(c, &q, NULL, NULL, &out)` |
| `VtFileDist_process(o, cb, data)`, `VtFileDist_parse(o, cb, data)` | `vt_file_distribution(c, &q, fn, userdata, NULL)`: one call fetches and walks a page |
| `VtUrlDist_setBefore`, `VtUrlDist_setAfter`, `VtUrlDist_setLimit`, `VtUrlDist_setAllInfo` | the `before`, `after`, `limit` and `reports` members of `struct vt_dist_query` (`reports` sends `allinfo=true`) |
| `VtUrlDist_getDistribution(o)` | `vt_url_distribution(c, &q, NULL, NULL, &out)` |
| `VtUrlDist_process(o, cb, data)`, `VtUrlDist_parse(o, cb, data)` | `vt_url_distribution(c, &q, fn, userdata, NULL)` |
| `progress_changed_cb`, `VtFileDistCb`, `VtUrlDistCb` | `vt_progress_fn`, `vt_file_dist_fn`, `vt_url_dist_fn`; timestamps, totals and positives are now `long long` |
| `VtObject_*`, `VtApiPage_*` (`alloc`, `new`, `get`, `put`, `free`, `register`, `shared`, `toJSON`, `toJSONstr`, `newByName`, `newFromJSON`, `setApiKey`, `resetBuffer`, `destructor`, `__VtApiPage_WriteCb`) | removed: these were the internal object system, and the client replaces them |
| `VT_JSON_FLAG_INDENT`, `VT_JSON_FLAG_DEBUG` | removed: pass jansson's own flags to `json_dumps()` |

### Behaviour fixes

These fixes change what goes over the wire or what a call returns, compared
with the legacy library:

* **Uploads send the real file again.** `vt_file_scan()` uploads the
  contents of the file. The legacy `VtFile_scan()` sent the path string as
  the file content. `vt_file_scan_mem()` uploads your buffer under your
  file name, whereas the legacy `VtFile_scanMemBuf()` ignored the buffer
  and read a disk file of that name. Big-file uploads send the file
  contents too. In the `scan` tool this affects `--filescan` and
  `--scaninput`.
* **Every query parameter is URL-escaped.** A key, hash, IP, domain, date or
  paging token containing `&`, `#`, `+`, a space or non-ASCII bytes can no
  longer add parameters or make the request fail. Multipart values were
  already safe and are still sent verbatim.
* **No length limits.** Long keys and values are sent in full. The legacy
  code truncated them or overflowed fixed buffers.
* **`url --all-info` and `--report-scan` are no longer swapped.** `--all-info`
  sends `all_info=1` and `--report-scan` sends `scan=1`.
* **No stale responses.** A failed request returns an error and never the
  previous request's response. The distribution tools stop at a failed
  page instead of processing the previous page again.
* **Search paging.** An offset is sent only with the call it is passed to.
  The next cursor comes from the response, an empty one means there are no
  more pages, and a used offset is never sent again.
* **Cancellation is per operation.** `vt_cancel()` stops the operation
  that is running and nothing after it. The legacy cancel flag stuck
  forever and failed every later operation.
* **Consistent error codes.** Every operation returns a `vt_err`, and the
  HTTP status, the libcurl code and a message are available from the
  client. The legacy mix of curl codes, HTTP statuses, -1 and stray string
  lengths is gone, and no failure is reported as success any more (for
  example a connection failure in `VtUrl_scan`, or a missing `upload_url`
  in `VtFile_scanBigFile`). The tools still print the same numbers in
  `Error: N`, and print the real libcurl code where the legacy tools
  printed a meaningless value.
* **No crashes on bad input or bad responses.** Long inputs, a JSON `null`
  where a string was expected (such as `"verbose_msg": null`), a
  connection failure before any response and NULL arguments all return
  errors instead of crashing.
* **The tools honour `VT_API_BASE_URL`,** and a library client takes its
  base URL as an argument, so both can point at a test server.
* **Connections are reused** across the GET lookups of one client (a POST
  always gets a connection of its own, so it is never sent twice), and
  only `http` and `https` are allowed, for redirects and upload URLs too.

## License

Apache License 2.0. See `COPYING`; every C source file (`.c` and `.h`)
carries the license header. Originally developed by VirusTotal S.L. (see
`AUTHORS`).
