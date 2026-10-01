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

/* The single request path.  Every endpoint ends up in vt__perform(). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "private.h"

/* upload_url and redirect targets come from the server: never let them
 * switch libcurl to another protocol (file://, gopher://, ...). */
#define VT_PROTOCOLS "http,https"

struct sink {
	vt_write_fn *fn; /* user sink, or NULL for the JSON buffer */
	void *ud;
	struct vt_buf *body;
};

static size_t on_write(char *p, size_t size, size_t nmemb, void *ud) {
	struct sink *s = ud;
	size_t n = size * nmemb; /* libcurl guarantees size == 1 */

	if (s->fn) return s->fn(p, n, s->ud) == n ? n : 0;
	vt__buf_putn(s->body, p, n);
	return s->body->oom ? 0 : n; /* 0 -> CURLE_WRITE_ERROR */
}

static int on_progress(void *ud, curl_off_t dltotal, curl_off_t dlnow,
                       curl_off_t ultotal, curl_off_t ulnow) {
	vt_client *c = ud;
	int stop = 0;

	if (c->progress)
		stop =
		    c->progress(c->progress_ud, dltotal, dlnow, ultotal, ulnow);
	/* checked after the user callback so a cancel issued inside it
	 * aborts on the same tick */
	if (stop || atomic_load(&c->cancel)) {
		c->aborted = true;
		return 1; /* -> CURLE_ABORTED_BY_CALLBACK */
	}
	return 0;
}

static bool status_ok(enum vt_accept a, long st) {
	switch (a) {
		case VT_ACCEPT_ANY:
			return true;
		case VT_ACCEPT_200:
			return st == 200;
		case VT_ACCEPT_200_302:
			return st == 200 || st == 302;
	}
	return false;
}

/* Content-Type libcurl 8.5 would guess for a file name (the table of
 * Curl_mime_contenttype()), else "application/octet-stream". */
static const char *guess_type(const char *filename) {
	static const struct {
		const char *ext;
		const char *type;
	} t[] = {
	    {".gif", "image/gif"},       {".jpg", "image/jpeg"},
	    {".jpeg", "image/jpeg"},     {".png", "image/png"},
	    {".svg", "image/svg+xml"},   {".txt", "text/plain"},
	    {".htm", "text/html"},       {".html", "text/html"},
	    {".pdf", "application/pdf"}, {".xml", "application/xml"},
	};
	size_t n = strlen(filename);

	for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
		size_t e = strlen(t[i].ext);
		if (n >= e && !strcasecmp(filename + n - e, t[i].ext))
			return t[i].type;
	}
	return "application/octet-stream";
}

static bool skipped(const struct vt_param *p) {
	return p->skip || (p->kind == VT_TEXT && !p->str);
}

/* URL = (rq->url | base + path) [ "?" name "=" esc(value) { "&" ... } ] */
static void build_url(const vt_client *c, const struct vt_req *rq,
                      struct vt_buf *u) {
	char sep = '?';

	vt__buf_puts(u, rq->url ? rq->url : c->base);
	if (!rq->url) vt__buf_puts(u, rq->path);
	if (rq->post) return;
	for (const struct vt_param *p = rq->params; p && p->name; p++) {
		if (skipped(p)) continue;
		vt__buf_putc(u, sep);
		sep = '&';
		vt__buf_puts(u, p->name);
		vt__buf_putc(u, '=');
		if (p->kind == VT_INT) { /* digits and '-' are unreserved */
			char num[24];
			snprintf(num, sizeof num, "%lld", p->num);
			vt__buf_puts(u, num);
		} else {
			vt__buf_escape(u, p->str);
		}
	}
}

/* One multipart part.  Returns VT_OK or the failure (recorded in c). */
static vt_err add_part(vt_client *c, curl_mime *mime,
                       const struct vt_param *p) {
	curl_mimepart *part = curl_mime_addpart(mime);
	char num[24];
	CURLcode rc;

	if (!part) return vt__fail(c, VT_ENOMEM, "curl_mime_addpart");
	rc = curl_mime_name(part, p->name);
	switch (p->kind) {
		case VT_TEXT:
			if (!rc)
				rc = curl_mime_data(part, p->str,
				                    CURL_ZERO_TERMINATED);
			break;
		case VT_INT:
			snprintf(num, sizeof num, "%lld", p->num);
			if (!rc)
				rc = curl_mime_data(part, num,
				                    CURL_ZERO_TERMINATED);
			break;
		case VT_FILE: /* filename = basename, type guessed by curl */
			if (!rc) rc = curl_mime_filedata(part, p->str);
			if (rc == CURLE_READ_ERROR) {
				c->curl_code = (int)rc;
				return vt__fail(c, VT_EIO, "cannot read '%s'",
				                p->str);
			}
			break;
		case VT_MEM: /* verbatim filename, explicit type */
			if (!rc) rc = curl_mime_data(part, p->data, p->len);
			if (!rc) rc = curl_mime_filename(part, p->str);
			if (!rc) rc = curl_mime_type(part, guess_type(p->str));
			break;
	}
	if (rc) {
		c->curl_code = (int)rc;
		return vt__fail(
		    c, rc == CURLE_OUT_OF_MEMORY ? VT_ENOMEM : VT_ECURL,
		    "multipart part '%s': %s", p->name, curl_easy_strerror(rc));
	}
	return VT_OK;
}

/* Applies every option of one request to the freshly reset handle.  All
 * of them are plain stores that can only fail with CURLE_OUT_OF_MEMORY
 * (string copies) or on a libcurl without the option. */
static CURLcode setup(vt_client *c, CURL *h, const struct vt_req *rq,
                      const char *url, struct sink *sink,
                      struct curl_slist *hdr, curl_mime *mime) {
	CURLcode rc = curl_easy_setopt(h, CURLOPT_URL, url);

	if (!rc) rc = curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, VT_PROTOCOLS);
	if (!rc)
		rc = curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS_STR,
		                      VT_PROTOCOLS);
	if (!rc) rc = curl_easy_setopt(h, CURLOPT_ERRORBUFFER, c->curl_errbuf);
	if (!rc) rc = curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
	if (!rc) rc = curl_easy_setopt(h, CURLOPT_NOPROGRESS, 0L);
	if (!rc)
		rc = curl_easy_setopt(h, CURLOPT_XFERINFOFUNCTION, on_progress);
	if (!rc) rc = curl_easy_setopt(h, CURLOPT_XFERINFODATA, c);
	if (!rc) rc = curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_write);
	if (!rc) rc = curl_easy_setopt(h, CURLOPT_WRITEDATA, sink);
	if (!rc && rq->follow)
		rc = curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
	if (!rc && mime) rc = curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdr);
	if (!rc && mime) rc = curl_easy_setopt(h, CURLOPT_MIMEPOST, mime);
	if (!rc && vt__log_level() >= 1)
		rc = curl_easy_setopt(h, CURLOPT_VERBOSE, 1L);
	return rc;
}

vt_err vt__perform(vt_client *c, const struct vt_req *rq, json_t **root) {
	struct vt_buf url = {}, body = {.max = VT_MAX_JSON_BODY};
	struct sink sink = {.fn = rq->sink, .ud = rq->sink_ud, .body = &body};
	struct curl_slist *hdr = nullptr;
	curl_mime *mime = nullptr;
	CURLcode rc;
	json_error_t jerr;
	json_t *j;
	vt_err e;

	if (root) *root = nullptr;
	if ((e = vt__begin(c, rq->keep_cancel))) return e;
	c->busy = true;

	if (rq->keep_cancel && atomic_load(&c->cancel)) {
		/* cancelled between two requests of one operation: do not
		 * even connect */
		c->curl_code = CURLE_ABORTED_BY_CALLBACK;
		e = vt__fail(c, VT_ECANCEL, "operation cancelled");
		goto out;
	}
	build_url(c, rq, &url);
	if (url.oom) {
		e = vt__fail(c, VT_ENOMEM, "building URL");
		goto out;
	}
	if (!c->curl && !(c->curl = curl_easy_init())) {
		c->curl_code = CURLE_FAILED_INIT;
		e = vt__fail(c, VT_ECURL, "curl_easy_init failed");
		goto out;
	}
	/* drops every option of the previous request but keeps its
	 * connections, DNS cache and TLS sessions */
	curl_easy_reset(c->curl);
	if (rq->post) {
		mime = curl_mime_init(c->curl);
		hdr = curl_slist_append(nullptr, "Expect:");
		if (!mime || !hdr) {
			e = vt__fail(c, VT_ENOMEM, "multipart setup");
			goto out;
		}
		for (const struct vt_param *p = rq->params; p && p->name; p++) {
			if (skipped(p)) continue;
			if ((e = add_part(c, mime, p))) goto out;
		}
	}
	rc = setup(c, c->curl, rq, url.data, &sink, hdr, mime);
	if (rc) {
		c->curl_code = (int)rc;
		e = vt__fail(c, VT_ECURL, "curl_easy_setopt: %s",
		             curl_easy_strerror(rc));
		goto out;
	}

	VT_LOG(1, "%s %s", rq->post ? "POST" : "GET", url.data);
	rc = curl_easy_perform(c->curl);
	(void)curl_easy_getinfo(c->curl, CURLINFO_RESPONSE_CODE,
	                        &c->http_status);
	if (rc != CURLE_OK) {
		const char *why =
		    c->curl_errbuf[0] ? c->curl_errbuf : curl_easy_strerror(rc);

		c->curl_code = (int)rc;
		if (rc == CURLE_ABORTED_BY_CALLBACK && c->aborted)
			e = vt__fail(c, VT_ECANCEL, "operation cancelled");
		else if (body.oom)
			e = vt__fail(
			    c, VT_ENOMEM,
			    "response body too large or out of memory");
		else if (rc == CURLE_READ_ERROR)
			e = vt__fail(c, VT_EIO, "%s", why);
		else
			e = vt__fail(c, VT_ECURL, "%s", why);
		goto out;
	}
	if (!status_ok(rq->accept, c->http_status)) {
		e = vt__fail(c, VT_EHTTP, "HTTP %ld", c->http_status);
		goto out;
	}
	if (rq->sink) goto out; /* e == VT_OK */
	VT_LOG(2, "body: %s", body.data ? body.data : "");
	/* json_loads (not json_loadb): the body is NUL-terminated and, as
	 * before, parsing stops at an embedded NUL; flags 0 = object/array */
	j = json_loads(body.data ? body.data : "", 0, &jerr);
	if (!j) {
		e = vt__fail(c, VT_EJSON, "JSON parse error: %s (line %d)",
		             jerr.text, jerr.line);
		goto out;
	}
	if (root)
		*root = j;
	else
		json_decref(j);
out:
	/* The handle keeps pointers to the mime and header list until the
	 * next reset; curl_mime_free() detaches the mime from it and the
	 * list is never read again before that reset. */
	curl_mime_free(mime);
	curl_slist_free_all(hdr);
	vt__buf_free(&url);
	vt__buf_free(&body);
	c->busy = false;
	return e;
}
