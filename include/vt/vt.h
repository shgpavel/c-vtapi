/*
Copyright 2014 VirusTotal S.L. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * vt/vt.h - minimal C client for the VirusTotal v2 API (libcurl + jansson).
 *
 * This is the only public header.  It is self-contained and valid C99 or
 * later and C++ (the library itself is built as C23).
 *
 * CONVENTIONS (they apply to every function unless its comment says
 * otherwise):
 *
 *  Naming.  vt_client_* functions create, destroy and configure a client;
 *    the other vt_* functions are operations or read the result of the
 *    last operation.  Typedefs exist only for the opaque client, the error
 *    enum and the callback types.
 *
 *  Errors.  Every network function returns a vt_err.  VT_OK (0) means
 *    success; anything else is a failure and the details of the most
 *    recent operation are available from vt_http_status(), vt_curl_code()
 *    and vt_errmsg() (except for a call rejected because the client is
 *    busy, see Callbacks).  Required pointer arguments must be non-NULL:
 *    a NULL client or a NULL required argument returns VT_EINVAL and
 *    sends nothing.  Functions that also reject an empty string say so;
 *    every other string, "" included, is sent as given.
 *
 *  Unused results.  Functions marked VT_NODISCARD warn when their result
 *    is ignored.  Before C23 and C++17 the attribute is GCC's
 *    warn_unused_result, which GCC does not let a (void) cast silence;
 *    consume the result instead, e.g. `if (vt_file_report(...)) {}`.
 *
 *  JSON results.  Functions that take `json_t **out` store a NEW reference
 *    in *out on VT_OK; the caller owns it and releases it with
 *    json_decref().  On any error *out is set to NULL, so
 *    json_decref(*out) is always safe.  `out` may be NULL when the caller
 *    does not want the body; it is then parsed (errors are still
 *    reported) and released.
 *
 *  Strings.  Every `const char *` argument is only read during the call
 *    and copied if kept; the caller keeps ownership.  Every returned
 *    `const char *` is borrowed: from the client (valid until the next
 *    operation on it or vt_client_free()) or from a json_t (valid while
 *    that json_t is alive).  The only strings the caller must free() are
 *    `*url` of vt_file_upload_url() and `*data` of vt_file_download_mem().
 *
 *  Threads.  A vt_client is NOT thread-safe: use it from one thread at a
 *    time.  Distinct clients may be used concurrently from different
 *    threads: the library has no shared mutable state apart from the
 *    atomic debug level, and libcurl runs with CURLOPT_NOSIGNAL so it
 *    never uses SIGALRM for timeouts.  vt_cancel() is the exception: it
 *    may be called from any thread and from a signal handler.
 *
 *  Signals.  The library installs no signal handlers and does not touch
 *    SIGPIPE.  libcurl runs with CURLOPT_NOSIGNAL, so it does not ignore
 *    SIGPIPE around transfers; it sends with MSG_NOSIGNAL (Linux) or
 *    SO_NOSIGPIPE (BSD/macOS) instead, so a peer closing the connection
 *    does not raise it there.  Writes done by your own callbacks (e.g.
 *    the download sink) follow your process's SIGPIPE disposition.
 *
 *  Connections.  Each client keeps one libcurl easy handle for its whole
 *    life, so connections, DNS results and TLS sessions are reused by its
 *    later operations.  Every request starts from reset options: nothing
 *    one request sets leaks into the next.  The GET lookups share the kept
 *    connections; libcurl re-sends a GET once if a reused connection dies
 *    before any response byte.  Every POST (scans, rescans, file/report,
 *    file/search, url/scan, url/report, comments/put and the upload of
 *    vt_file_scan_big()) uses a new connection that is closed afterwards,
 *    so a POST is never sent twice.  Only "http" and "https" URLs are
 *    used, for redirects too ("http" alone with a libcurl without TLS).
 *
 *  Callbacks.  All callbacks run synchronously on the thread that called
 *    the library.  The progress and write callbacks run inside the
 *    transfer: calling another operation on the same client from them
 *    returns VT_EINVAL and records nothing, so the client's diagnostics
 *    keep describing the running operation.  Distribution callbacks run
 *    after the transfer and may use the client; the diagnostics read after
 *    the distribution call still describe that call, not the nested ones.
 *    The item and strings they receive are borrowed and valid only during
 *    the callback: treat the item as read-only (do not add, remove or
 *    replace members, the strings point into it) and keep it with
 *    json_incref() or json_deep_copy(), or keep *out.
 *
 *  ABI.  The public structs (struct vt_rescan_opts, struct vt_dist_query)
 *    are allocated by the caller and read in full by the library, so their
 *    layout is part of the ABI: members are only ever added together with
 *    a SONAME bump.
 *
 *  Wire.  Query-string values are percent-encoded exactly like
 *    curl_easy_escape() (unreserved A-Z a-z 0-9 - . _ ~ kept, everything
 *    else %XX uppercase).  Multipart values are sent verbatim.  A client
 *    without an API key sends an empty "apikey" value.
 */

#ifndef VT_VT_H
#define VT_VT_H 1

#include <jansson.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VT_VERSION_MAJOR 1
#define VT_VERSION_MINOR 0
#define VT_VERSION_PATCH 0
/* 0xMMmmpp, like LIBCURL_VERSION_NUM / JANSSON_VERSION_HEX */
#define VT_VERSION_NUM \
	((VT_VERSION_MAJOR << 16) | (VT_VERSION_MINOR << 8) | VT_VERSION_PATCH)

/* Base URL used when vt_client_new() gets NULL or "". */
#define VT_DEFAULT_BASE_URL "https://www.virustotal.com/vtapi/v2/"

#if defined(__GNUC__)
#define VT_API __attribute__((visibility("default")))
#else
#define VT_API
#endif

/* [[nodiscard]] only where the language has it: in C it needs C23 (gcc
 * 9/10 report a post-C17 __STDC_VERSION__ for -std=c2x without supporting
 * the attribute, hence __has_c_attribute), in C++ it needs C++17. */
#if defined(__cplusplus)
#if __cplusplus >= 201703L
#define VT_NODISCARD [[nodiscard]]
#endif
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ > 201710L && \
    defined(__has_c_attribute)
#if __has_c_attribute(nodiscard)
#define VT_NODISCARD [[nodiscard]]
#endif
#endif
#if !defined(VT_NODISCARD) && defined(__GNUC__)
#define VT_NODISCARD __attribute__((warn_unused_result))
#endif
#ifndef VT_NODISCARD
#define VT_NODISCARD
#endif

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

typedef enum vt_err {
	VT_OK = 0,  /* success */
	VT_EINVAL,  /* invalid argument or client busy; nothing sent */
	VT_ENOMEM,  /* allocation failed (or response body over the cap) */
	VT_ECURL,   /* libcurl setup/transfer failed; see vt_curl_code() */
	VT_EHTTP,   /* HTTP status rejected by the endpoint's policy;
	               see vt_http_status() */
	VT_EJSON,   /* body is empty or not a JSON object/array */
	VT_EPROTO,  /* JSON is valid but lacks what the operation needs */
	VT_ECANCEL, /* cancelled by vt_cancel() or the progress callback;
	               vt_curl_code() == 42 (CURLE_ABORTED_BY_CALLBACK) */
	VT_EIO,     /* a local file to upload does not exist or is not
	               readable; vt_curl_code() == 26 (CURLE_READ_ERROR) */
} vt_err;

/* Static English text for `err` (never NULL).  Thread-safe. */
VT_API const char *vt_strerror(vt_err err);

/* VT_VERSION_NUM of the library actually linked, to detect a mismatch
 * between this header and the shared library at run time. */
VT_API unsigned vt_version(void);

/*
 * Debug level for every client in the process (atomic).  0 = silent
 * (default), >= 1 = request/error lines on stderr plus CURLOPT_VERBOSE,
 * >= 2 = also response bodies.  Debug output may contain the API key.
 * The initial level comes from the environment variable VT_DEBUG (atoi
 * semantics), read once when the first client is created or at the first
 * vt_set_debug() call, whichever comes first; vt_set_debug() always
 * overrides it.
 */
VT_API void vt_set_debug(int level);

/* ------------------------------------------------------------------ */
/* Client                                                              */
/* ------------------------------------------------------------------ */

typedef struct vt_client vt_client;

/*
 * Progress callback, called on every libcurl progress tick of every
 * operation (including while connecting) with the byte counters of the
 * current transfer (same meaning as CURLOPT_XFERINFOFUNCTION).  Return 0
 * to continue, non-zero to abort the operation with VT_ECANCEL.
 */
typedef int vt_progress_fn(void *userdata, int64_t dltotal, int64_t dlnow,
                           int64_t ultotal, int64_t ulnow);

/*
 * Creates a client.  `apikey` may be NULL (requests then carry an empty
 * apikey; vt_comments_get() refuses to run).  `base_url` is the prefix
 * every endpoint path is appended to, used verbatim (keep the trailing
 * '/'); NULL or "" selects VT_DEFAULT_BASE_URL.  The library does NOT read
 * VT_API_BASE_URL itself: applications pass getenv("VT_API_BASE_URL")
 * here if they want that override (the bundled tools do).  Both strings
 * are copied.  Returns NULL on allocation failure.  The first call also
 * performs the process-wide libcurl initialisation (pthread_once).
 */
VT_NODISCARD VT_API vt_client *vt_client_new(const char *apikey,
                                             const char *base_url);

/* Destroys `c` and closes its connections.  NULL is a no-op.  Must not be
 * called during an operation on `c` (e.g. from one of its callbacks). */
VT_API void vt_client_free(vt_client *c);

/* Replaces the API key (copied; NULL clears it).  Returns VT_OK,
 * VT_EINVAL (c NULL) or VT_ENOMEM, in which case the old key stays in
 * use. */
VT_NODISCARD VT_API vt_err vt_client_set_apikey(vt_client *c,
                                                const char *apikey);

/* Installs (or with fn == NULL removes) the progress callback.  It stays
 * installed for all later operations. */
VT_API void vt_client_set_progress(vt_client *c, vt_progress_fn *fn,
                                   void *userdata);

/*
 * Requests cancellation of the operation currently running on `c`; it
 * then fails with VT_ECANCEL at its next progress tick.  The request is
 * cleared when the next operation starts, so a cancel issued while no
 * operation runs has no effect.  An operation made of several requests
 * (vt_file_scan_big()) clears it only once, at its start.  Safe from any
 * thread and from a signal handler (lock-free atomic store).  NULL is a
 * no-op.
 */
VT_API void vt_cancel(vt_client *c);

/* HTTP status of the last operation's final response, 0 if none was
 * received (or c is NULL).  Also set on VT_OK: endpoints that accept any
 * status (url, ip, domain, comments, upload_url) report it here. */
VT_API long vt_http_status(const vt_client *c);

/* CURLcode of the last operation, 0 if libcurl reported no error. */
VT_API int vt_curl_code(const vt_client *c);

/* Human-readable description of the last operation's result, e.g.
 * "Couldn't connect to server", "HTTP 403", "JSON parse error: ...".
 * Never NULL.  Borrowed from `c`: valid until the next operation on it. */
VT_API const char *vt_errmsg(const vt_client *c);

/* ------------------------------------------------------------------ */
/* Helpers for the returned JSON (all NULL-safe, all borrowed results) */
/* ------------------------------------------------------------------ */

/*
 * If `resp` is an object with a top-level "response_code" member, stores
 * (int)json_integer_value(member) in *code and returns true (a
 * non-integer member yields 0, as in the old VtResponse_getIntValue).
 * Otherwise returns false and leaves *code untouched.
 */
VT_API bool vt_response_code(const json_t *resp, int *code);

/* Top-level "verbose_msg" if it is a non-empty string, else NULL. */
VT_API const char *vt_verbose_msg(const json_t *resp);

/* Top-level "offset" of a vt_file_search() result if it is a non-empty
 * string (the cursor of the next page), else NULL. */
VT_API const char *vt_next_offset(const json_t *resp);

/* ------------------------------------------------------------------ */
/* file/...                                                            */
/* ------------------------------------------------------------------ */

/*
 * POST file/scan.  Multipart: "file" = contents of `path` (part filename
 * = basename, Content-Type guessed from the extension, else
 * application/octet-stream), "filename" = `path` as given, "notify_url"
 * if non-NULL and non-empty, "apikey".  An empty `path` is VT_EINVAL;
 * VT_EIO (nothing sent) if `path` does not exist or is not readable
 * (stat() or access() fails).  Anything else is streamed as read until
 * EOF: pipes and devices work, a directory uploads as an empty part and a
 * read error partway through is not detected (a short upload).  Requires
 * HTTP 200.  No size limit here; files of 32 MiB and more should go
 * through vt_file_scan_big().
 */
VT_NODISCARD VT_API vt_err vt_file_scan(vt_client *c, const char *path,
                                        const char *notify_url, json_t **out);

/*
 * POST file/scan with an in-memory file.  "file" = data[0..len) with part
 * filename = `filename` verbatim and Content-Type guessed from it (else
 * application/octet-stream); then "notify_url" (non-NULL, non-empty),
 * "apikey".  `filename` must be non-empty; len must be < 32 MiB
 * (33554432); data may be NULL only if len == 0.  The buffer is copied.
 */
VT_NODISCARD VT_API vt_err vt_file_scan_mem(vt_client *c, const char *filename,
                                            const void *data, size_t len,
                                            const char *notify_url,
                                            json_t **out);

/*
 * Large-file scan: GET file/scan/upload_url, then POST the absolute URL it
 * returns (never prefixed with the base URL, redirects followed) with
 * "file" = contents of `path` (basename filename) and "filename" = `path`;
 * no apikey part.  An empty `path` is VT_EINVAL (nothing sent).  VT_EPROTO
 * if the first response has no non-empty "upload_url"; VT_EIO if `path`
 * does not exist or is not readable (detected after step 1, nothing
 * uploaded; anything else is streamed as for vt_file_scan()).  Both
 * requests form one operation: a vt_cancel() at any time, including
 * between them, fails it with VT_ECANCEL.  The final response must be
 * HTTP 200; *out is its JSON.
 */
VT_NODISCARD VT_API vt_err vt_file_scan_big(vt_client *c, const char *path,
                                            json_t **out);

/*
 * GET file/scan/upload_url?apikey=K (redirects followed, any HTTP status).
 * On VT_OK *url is a malloc'd string the caller must free(); otherwise
 * *url is NULL.  VT_EPROTO if the JSON has no "upload_url" string or it
 * is empty.
 */
VT_NODISCARD VT_API vt_err vt_file_upload_url(vt_client *c, char **url);

/* Optional parameters of vt_file_rescan(); zero-initialise, set what you
 * need.  A NULL options pointer means all zero.  Part of the ABI (see
 * above). */
struct vt_rescan_opts {
	int64_t date;             /* != 0: "date" = these seconds since the
	                             Unix epoch as UTC "%Y%m%d%H%M%S", i.e.
	                             YYYYmmddHHMMSS for years 1000..9999;
	                             other years get %Y as the C library
	                             prints it (glibc: no zero padding, '-'
	                             before negative years) */
	int period;               /* != 0: "period" (decimal) */
	int repeat;               /* != 0: "repeat" (decimal) */
	const char *notify_url;   /* != NULL: "notify_url" (even "") */
	bool notify_changes_only; /* "notify_changes_only" = "1", only
	                             when notify_url != NULL */
};

/*
 * POST file/rescan.  Multipart, in order: "resource" (a hash or a
 * comma-separated list), then the options above in declaration order,
 * then "apikey".  VT_EINVAL if `date` does not fit in time_t, cannot be
 * converted to UTC or its UTC year exceeds INT_MAX.  Requires HTTP 200; a
 * multi-resource rescan yields a JSON array.
 */
VT_NODISCARD VT_API vt_err vt_file_rescan(vt_client *c, const char *resource,
                                          const struct vt_rescan_opts *opts,
                                          json_t **out);

/* POST file/rescan/delete: "resource", "apikey".  Requires HTTP 200. */
VT_NODISCARD VT_API vt_err vt_file_rescan_delete(vt_client *c,
                                                 const char *resource,
                                                 json_t **out);

/* POST file/report: "resource", "apikey".  Requires HTTP 200. */
VT_NODISCARD VT_API vt_err vt_file_report(vt_client *c, const char *resource,
                                          json_t **out);

/*
 * POST file/search: "query", "apikey", then "offset" iff offset != NULL
 * (an empty string is sent).  Nothing is remembered between calls: to get
 * the next page pass vt_next_offset(*out) as `offset` of the next call.
 * The hashes are the strings in the "hashes" array of *out (the array may
 * be missing on the last page; that is still VT_OK).  `query` must be
 * non-empty.  Requires HTTP 200.
 */
VT_NODISCARD VT_API vt_err vt_file_search(vt_client *c, const char *query,
                                          const char *offset, json_t **out);

/* GET file/clusters?apikey=K&date=D (`date` "YYYY-MM-DD", non-empty).
 * The clusters are the objects in the "clusters" array of *out.  Requires
 * HTTP 200. */
VT_NODISCARD VT_API vt_err vt_file_clusters(vt_client *c, const char *date,
                                            json_t **out);

/*
 * Download sink: receives the body in order, in chunks.  Return `len` to
 * continue; any other value aborts the download with VT_ECURL
 * (vt_curl_code() == 23, CURLE_WRITE_ERROR).
 */
typedef size_t vt_write_fn(const void *data, size_t len, void *userdata);

/*
 * GET file/download?apikey=K&hash=H, following redirects, streaming the
 * final response body to `fn` WHATEVER its status (an error page reaches
 * the sink too).  Accepts final status 200 or 302, else VT_EHTTP.  `hash`
 * must be non-empty.
 */
VT_NODISCARD VT_API vt_err vt_file_download(vt_client *c, const char *hash,
                                            vt_write_fn *fn, void *userdata);

/* vt_file_download() into a caller-owned stream opened for writing (not
 * closed; a short fwrite gives VT_ECURL/23). */
VT_NODISCARD VT_API vt_err vt_file_download_fp(vt_client *c, const char *hash,
                                               FILE *fp);

/*
 * vt_file_download() into memory.  On VT_OK *data is a malloc'd buffer of
 * *len bytes (plus a terminating NUL not counted in *len) that the caller
 * must free(); otherwise *data is NULL and *len is 0.
 */
VT_NODISCARD VT_API vt_err vt_file_download_mem(vt_client *c, const char *hash,
                                                void **data, size_t *len);

/* ------------------------------------------------------------------ */
/* url/..., ip-address/..., domain/..., comments/...                   */
/* These endpoints accept ANY HTTP status: a JSON error body is VT_OK  */
/* (check vt_http_status()); a non-JSON body is VT_EJSON.              */
/* ------------------------------------------------------------------ */

/* POST url/scan: "url" (verbatim; may hold several newline-separated
 * URLs), "apikey". */
VT_NODISCARD VT_API vt_err vt_url_scan(vt_client *c, const char *url,
                                       json_t **out);

/* Flags for vt_url_report(). */
enum {
	VT_URL_REPORT_SCAN = 1u << 0,     /* send "scan" = "1" */
	VT_URL_REPORT_ALL_INFO = 1u << 1, /* send "all_info" = "1" */
};

/* POST url/report: "resource", "apikey", then "scan" and "all_info" as
 * selected by `flags` (never sent as "0").  Unknown flag bits give
 * VT_EINVAL. */
VT_NODISCARD VT_API vt_err vt_url_report(vt_client *c, const char *resource,
                                         unsigned flags, json_t **out);

/* GET ip-address/report?apikey=K&ip=IP */
VT_NODISCARD VT_API vt_err vt_ip_report(vt_client *c, const char *ip,
                                        json_t **out);

/* GET domain/report?apikey=K&domain=D */
VT_NODISCARD VT_API vt_err vt_domain_report(vt_client *c, const char *domain,
                                            json_t **out);

/* POST comments/put: "resource", "comment", "apikey". */
VT_NODISCARD VT_API vt_err vt_comments_put(vt_client *c, const char *resource,
                                           const char *comment, json_t **out);

/*
 * GET comments/get?apikey=K&resource=R[&before=B]; "before" is sent iff
 * before != NULL (an empty string is sent).  VT_EINVAL if the client has
 * no API key.  Paging is manual: pass the datetime token of the oldest
 * comment as `before`.
 */
VT_NODISCARD VT_API vt_err vt_comments_get(vt_client *c, const char *resource,
                                           const char *before, json_t **out);

/* ------------------------------------------------------------------ */
/* file/distribution, url/distribution (private-API feeds)             */
/* ------------------------------------------------------------------ */

/*
 * Query state of a distribution feed, owned by the caller (part of the
 * ABI, see above).  Each member is sent only when non-zero, in this
 * order: &before=%lld, &after=%lld, &reports=true (file) / &allinfo=true
 * (url), &limit=%d.  After every element that validates, `after` is set
 * to that element's "timestamp", so calling again with the same struct
 * fetches the next page; pass a copy to fetch a page without advancing.
 */
struct vt_dist_query {
	long long before;
	long long after;
	int limit;
	bool reports; /* file: "reports=true"; url: "allinfo=true" */
};

/* Called once per validated element of a file/distribution page.  `name`
 * may be NULL.  Everything is borrowed for the duration of the call (see
 * Callbacks above). */
typedef void vt_file_dist_fn(const char *link, long long timestamp,
                             const char *sha256, const char *name, json_t *item,
                             void *userdata);

/* Called once per validated element of a url/distribution page. */
typedef void vt_url_dist_fn(const char *url, long long timestamp,
                            long long total, long long positives, json_t *item,
                            void *userdata);

/*
 * GET file/distribution (one page), then walk the array in order: every
 * element must be an object with string "link", string "sha256", integer
 * "timestamp" and optional string "name"; for each valid element
 * q->after = timestamp, then fn(...) if fn != NULL.  The first invalid
 * element stops the walk with VT_EPROTO (earlier callbacks have already
 * run and q->after keeps the last valid timestamp).  A body that is not
 * an array is VT_EPROTO.  Requires HTTP 200.  q may be NULL (no optional
 * parameters, nothing updated).
 */
VT_NODISCARD VT_API vt_err vt_file_distribution(vt_client *c,
                                                struct vt_dist_query *q,
                                                vt_file_dist_fn *fn,
                                                void *userdata, json_t **out);

/* As vt_file_distribution() for url/distribution; elements need string
 * "url" and integer "timestamp", "total" and "positives". */
VT_NODISCARD VT_API vt_err vt_url_distribution(vt_client *c,
                                               struct vt_dist_query *q,
                                               vt_url_dist_fn *fn,
                                               void *userdata, json_t **out);

#ifdef __cplusplus
}
#endif

#endif /* VT_VT_H */
