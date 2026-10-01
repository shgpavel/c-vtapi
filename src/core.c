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

/* Client lifecycle, per-operation result state, logging, JSON helpers. */

#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "private.h"

/* ---- process-wide state: the once-guard and the atomic debug level ---- */

static pthread_once_t vt__once = PTHREAD_ONCE_INIT;
static atomic_int vt__level;

static void global_init(void) {
	const char *s = getenv("VT_DEBUG");
	long v = s ? strtol(s, nullptr, 10) : 0;

	/* libcurl >= 7.84 makes this thread-safe and reference counted; we
	 * take one reference for the life of the process and never drop it,
	 * so an application's own init/cleanup pairs cannot tear libcurl
	 * down under a live client.  A failure is not cached: curl_easy_init()
	 * retries the global init and returns NULL, which vt__perform()
	 * reports as VT_ECURL/CURLE_FAILED_INIT. */
	(void)curl_global_init(CURL_GLOBAL_DEFAULT);
	atomic_store(&vt__level, v < 0 ? 0 : v > INT_MAX ? INT_MAX : (int)v);
}

int vt__log_level(void) {
	return atomic_load_explicit(&vt__level, memory_order_relaxed);
}

void vt_set_debug(int level) {
	pthread_once(&vt__once, global_init); /* VT_DEBUG must not win later */
	atomic_store(&vt__level, level < 0 ? 0 : level);
}

void vt__log(const char *func, int line, const char *fmt, ...) {
	va_list ap;

	flockfile(stderr); /* one line, even with several threads logging */
	fprintf(stderr, "c-vtapi:%s:%d: ", func, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	funlockfile(stderr);
}

/* ---- errors ---- */

const char *vt_strerror(vt_err err) {
	switch (err) {
		case VT_OK:
			return "no error";
		case VT_EINVAL:
			return "invalid argument";
		case VT_ENOMEM:
			return "out of memory";
		case VT_ECURL:
			return "transfer failed";
		case VT_EHTTP:
			return "unexpected HTTP status";
		case VT_EJSON:
			return "response is not JSON";
		case VT_EPROTO:
			return "unexpected response content";
		case VT_ECANCEL:
			return "operation cancelled";
		case VT_EIO:
			return "cannot read local file";
	}
	return "unknown error";
}

unsigned vt_version(void) {
	return (unsigned)VT_VERSION_NUM;
}

vt_err vt__begin(vt_client *c, bool keep_cancel) {
	if (!c) return VT_EINVAL;
	if (c->busy) return VT_EINVAL; /* re-entered from a callback */
	free(c->msg);
	c->msg = nullptr;
	c->last = VT_OK;
	c->http_status = 0;
	c->curl_code = 0;
	c->curl_errbuf[0] = '\0';
	c->aborted = false;
	/* a cancel is not sticky: it only hits the operation it was issued
	 * during (or the next request of that same operation) */
	if (!keep_cancel) atomic_store(&c->cancel, false);
	return VT_OK;
}

[[gnu::format(printf, 3, 0)]] static vt_err vfail(vt_client *c, vt_err err,
                                                  const char *fmt, va_list ap) {
	char *msg = nullptr;
	va_list ap2;
	int n;

	c->last = err;
	va_copy(ap2, ap);
	n = vsnprintf(nullptr, 0, fmt, ap2);
	va_end(ap2);
	if (n >= 0 && (msg = malloc((size_t)n + 1)))
		vsnprintf(msg, (size_t)n + 1, fmt, ap);
	free(c->msg);
	c->msg = msg; /* NULL on OOM: vt_errmsg() falls back */
	VT_LOG(1, "error %d: %s", (int)err, vt_errmsg(c));
	return err;
}

vt_err vt__fail(vt_client *c, vt_err err, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	err = vfail(c, err, fmt, ap);
	va_end(ap);
	return err;
}

vt_err vt__inval(vt_client *c, const char *fmt, ...) {
	va_list ap;
	vt_err e = vt__begin(c, false);

	if (e) return e; /* NULL or busy client: leave its state alone */
	va_start(ap, fmt);
	e = vfail(c, VT_EINVAL, fmt, ap);
	va_end(ap);
	return e;
}

long vt_http_status(const vt_client *c) {
	return c ? c->http_status : 0;
}

int vt_curl_code(const vt_client *c) {
	return c ? c->curl_code : 0;
}

const char *vt_errmsg(const vt_client *c) {
	if (!c) return vt_strerror(VT_EINVAL);
	return c->msg ? c->msg : vt_strerror(c->last);
}

/* ---- client ---- */

vt_client *vt_client_new(const char *apikey, const char *base_url) {
	vt_client *c;

	pthread_once(&vt__once, global_init);
	c = calloc(1, sizeof *c);
	if (!c) return nullptr;
	atomic_init(&c->cancel, false);
	c->base =
	    strdup(vt__nonempty(base_url) ? base_url : VT_DEFAULT_BASE_URL);
	if (!c->base || (apikey && !(c->apikey = strdup(apikey)))) {
		vt_client_free(c);
		return nullptr;
	}
	return c;
}

void vt_client_free(vt_client *c) {
	if (!c) return;
	curl_easy_cleanup(c->curl); /* NULL is a no-op */
	free(c->apikey);
	free(c->base);
	free(c->msg);
	free(c);
}

vt_err vt_client_set_apikey(vt_client *c, const char *apikey) {
	char *k = nullptr;

	if (!c) return VT_EINVAL;
	if (apikey && !(k = strdup(apikey))) return VT_ENOMEM;
	free(c->apikey);
	c->apikey = k;
	return VT_OK;
}

void vt_client_set_progress(vt_client *c, vt_progress_fn *fn, void *ud) {
	if (!c) return;
	c->progress = fn;
	c->progress_ud = ud;
}

void vt_cancel(vt_client *c) {
	if (c) atomic_store(&c->cancel, true);
}

/* ---- JSON helpers ---- */

bool vt_response_code(const json_t *resp, int *code) {
	json_t *v = json_object_get(resp, "response_code");

	if (!v || !code) return false;
	*code = (int)json_integer_value(v);
	return true;
}

const char *vt_verbose_msg(const json_t *resp) {
	return vt__nonempty(
	    json_string_value(json_object_get(resp, "verbose_msg")));
}

const char *vt_next_offset(const json_t *resp) {
	return vt__nonempty(json_string_value(json_object_get(resp, "offset")));
}
