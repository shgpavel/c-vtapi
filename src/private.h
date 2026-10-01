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

/* Library-internal declarations.  Never installed. */

#ifndef VT_PRIVATE_H
#define VT_PRIVATE_H 1

#include <curl/curl.h>
#include <stdatomic.h>

#include "vt/vt.h"

/* vt_cancel() is documented as async-signal-safe. */
static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "atomic_bool must be lock-free");

/* Cap for bodies buffered for JSON parsing (not for downloads). */
#define VT_MAX_JSON_BODY ((size_t)256 * 1024 * 1024)
/* vt_file_scan_mem() limit, kept from VtFile_scanMemBuf. */
#define VT_MAX_MEM_SCAN ((size_t)32 * 1024 * 1024)

/* ---------------------------------------------------------------- */
/* Client                                                            */
/* ---------------------------------------------------------------- */

struct vt_client {
	char *apikey; /* owned; NULL = unset */
	char *base;   /* owned; never NULL */
	CURL *curl;   /* owned; created by the first request, then reused */
	vt_progress_fn *progress;
	void *progress_ud;
	atomic_bool cancel; /* set by vt_cancel(), cleared per operation */
	bool aborted;       /* xferinfo asked libcurl to abort */
	bool busy;          /* inside vt__perform() */
	/* result of the last operation */
	vt_err last;
	long http_status;
	int curl_code;
	char *msg; /* owned, NULL = use vt_strerror(last) */
	char curl_errbuf[CURL_ERROR_SIZE]; /* CURLOPT_ERRORBUFFER */
};

/* Starts a request: clears the previous result and, unless `keep_cancel`
 * (a later request of the same operation), the cancel flag.  Returns
 * VT_EINVAL if c is NULL or busy. */
vt_err vt__begin(vt_client *c, bool keep_cancel);

/* Records a failure (formatted message, logged at level 1) and returns
 * `err`.  Allocation failure of the message is tolerated. */
[[gnu::format(printf, 3, 4)]] vt_err vt__fail(vt_client *c, vt_err err,
                                              const char *fmt, ...);

/* vt__begin() + vt__fail(VT_EINVAL): argument validation in endpoints. */
[[gnu::format(printf, 2, 3)]] vt_err vt__inval(vt_client *c, const char *fmt,
                                               ...);

/* Value sent for "apikey": the key or "" when unset. */
static inline const char *vt__key(const vt_client *c) {
	return c->apikey ? c->apikey : "";
}

/* NULL for NULL or "" (for "sent iff non-empty" parameters). */
static inline const char *vt__nonempty(const char *s) {
	return (s && *s) ? s : nullptr;
}

static inline void vt__out_init(json_t **out) {
	if (out) *out = nullptr;
}

/* ---------------------------------------------------------------- */
/* Growable byte buffer (always NUL-terminated, sticky OOM flag)     */
/* ---------------------------------------------------------------- */

struct vt_buf {
	char *data; /* NULL until the first byte */
	size_t len;
	size_t cap;
	size_t max; /* 0 = unlimited; exceeding it sets oom */
	bool oom;   /* once set, appends are no-ops */
};

void vt__buf_putn(struct vt_buf *b, const void *p, size_t n);
void vt__buf_puts(struct vt_buf *b, const char *s);
void vt__buf_putc(struct vt_buf *b, char ch);
/* Appends s percent-encoded exactly like curl_easy_escape(). */
void vt__buf_escape(struct vt_buf *b, const char *s);
void vt__buf_free(struct vt_buf *b);

/* ---------------------------------------------------------------- */
/* The single request path                                           */
/* ---------------------------------------------------------------- */

enum vt_kind {
	VT_TEXT = 0, /* str, NUL-terminated */
	VT_INT,      /* num, formatted "%lld" */
	VT_FILE,     /* multipart only: file at path `str` (basename) */
	VT_MEM,      /* multipart only: data/len, part filename `str` */
};

/* One query parameter (GET) or multipart part (POST).  Arrays are
 * terminated by an entry with name == NULL. */
struct vt_param {
	const char *name;
	enum vt_kind kind;
	const char *str;
	long long num;
	const void *data;
	size_t len;
	bool skip; /* omit this entry; VT_TEXT with str == NULL also omits */
};

/* clang-format off */
#define VT_P_TEXT(n, v) {.name = (n), .kind = VT_TEXT, .str = (v)}
#define VT_P_INT(n, v) \
	{.name = (n), .kind = VT_INT, .num = (v), .skip = ((v) == 0)}
#define VT_P_FILE(n, path) {.name = (n), .kind = VT_FILE, .str = (path)}
#define VT_P_MEM(n, fname, p, l) \
	{.name = (n), .kind = VT_MEM, .str = (fname), .data = (p), .len = (l)}
#define VT_P_END {}
/* clang-format on */

enum vt_accept {
	VT_ACCEPT_ANY = 0, /* url, ip, domain, comments, upload_url */
	VT_ACCEPT_200,     /* file/..., distribution */
	VT_ACCEPT_200_302, /* file/download */
};

struct vt_req {
	const char *path;              /* appended to c->base, or ... */
	const char *url;               /* ... absolute URL used verbatim */
	bool post;                     /* multipart POST, else GET+query */
	bool follow;                   /* CURLOPT_FOLLOWLOCATION */
	bool keep_cancel;              /* continues an operation: a pending
	                                  vt_cancel() still applies */
	enum vt_accept accept;         /* status policy */
	const struct vt_param *params; /* terminated by VT_P_END */
	vt_write_fn *sink;             /* NULL: buffer + parse JSON */
	void *sink_ud;
};

/*
 * Performs one request on the client's reused libcurl handle: builds the
 * URL (escaped query) or the multipart body, runs it with progress/cancel,
 * applies the status policy and, when rq->sink is NULL, parses the body.
 * On VT_OK with rq->sink == NULL, *root (if root != NULL) holds a new
 * reference; otherwise *root is NULL and a parsed body is dropped.
 * Records the result in c (vt_http_status/vt_curl_code/vt_errmsg).
 */
vt_err vt__perform(vt_client *c, const struct vt_req *rq, json_t **root);

/* ---------------------------------------------------------------- */
/* Logging (stderr; not part of any contract)                        */
/* ---------------------------------------------------------------- */

int vt__log_level(void);
[[gnu::format(printf, 3, 4)]] void vt__log(const char *func, int line,
                                           const char *fmt, ...);

#define VT_LOG(lvl, fmt, ...)                                    \
	do {                                                     \
		if (vt__log_level() >= (lvl))                    \
			vt__log(__func__, __LINE__,              \
			        fmt __VA_OPT__(, ) __VA_ARGS__); \
	} while (0)

#endif /* VT_PRIVATE_H */
