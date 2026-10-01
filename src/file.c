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

/* file/... endpoints.  Each is validation + one declarative request. */

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "private.h"

vt_err vt_file_scan(vt_client *c, const char *path, const char *notify_url,
                    json_t **out) {
	vt__out_init(out);
	if (!c || !path || !*path) return vt__inval(c, "path required");
	const struct vt_param params[] = {
	    VT_P_FILE("file", path), /* the file's bytes */
	    VT_P_TEXT("filename", path),
	    VT_P_TEXT("notify_url", vt__nonempty(notify_url)),
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "file/scan",
	    .post = true,
	    .accept = VT_ACCEPT_200,
	    .params = params,
	};
	return vt__perform(c, &rq, out);
}

vt_err vt_file_scan_mem(vt_client *c, const char *filename, const void *data,
                        size_t len, const char *notify_url, json_t **out) {
	vt__out_init(out);
	if (!c || !filename || !*filename || len >= VT_MAX_MEM_SCAN ||
	    (!data && len))
		return vt__inval(c, "filename required, data < 32 MiB");
	const struct vt_param params[] = {
	    VT_P_MEM("file", filename, data ? data : "", len),
	    VT_P_TEXT("notify_url", vt__nonempty(notify_url)),
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "file/scan",
	    .post = true,
	    .accept = VT_ACCEPT_200,
	    .params = params,
	};
	return vt__perform(c, &rq, out);
}

vt_err vt_file_upload_url(vt_client *c, char **url) {
	json_t *root;
	const char *u;
	vt_err e;

	if (url) *url = nullptr;
	if (!c || !url) return vt__inval(c, "url out-pointer required");
	const struct vt_param params[] = {
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "file/scan/upload_url",
	    .follow = true,
	    .accept = VT_ACCEPT_ANY,
	    .params = params,
	};
	if ((e = vt__perform(c, &rq, &root))) return e;
	u = json_string_value(json_object_get(root, "upload_url"));
	if (!u || !*u)
		e = vt__fail(c, VT_EPROTO, "response has no upload_url");
	else if (!(*url = strdup(u)))
		e = vt__fail(c, VT_ENOMEM, "strdup");
	json_decref(root);
	return e;
}

vt_err vt_file_scan_big(vt_client *c, const char *path, json_t **out) {
	char *url;
	vt_err e;

	vt__out_init(out);
	if (!c || !path || !*path) return vt__inval(c, "path required");
	/* step 1 starts the operation (and clears a stale vt_cancel()) */
	if ((e = vt_file_upload_url(c, &url))) return e;
	/* the file's bytes and its path, but no apikey part */
	const struct vt_param params[] = {
	    VT_P_FILE("file", path),
	    VT_P_TEXT("filename", path),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .url = url,
	    .post = true,
	    .follow = true,
	    .keep_cancel = true, /* a cancel since step 1 still applies */
	    .accept = VT_ACCEPT_200,
	    .params = params,
	};
	e = vt__perform(c, &rq, out);
	free(url);
	return e;
}

vt_err vt_file_rescan(vt_client *c, const char *resource,
                      const struct vt_rescan_opts *opts, json_t **out) {
	static const struct vt_rescan_opts none = {};
	const struct vt_rescan_opts *o = opts ? opts : &none;
	time_t t = (time_t)o->date;
	/* %Y has at most 11 characters for any year gmtime_r can return
	 * (int tm_year), so 32 bytes can never truncate */
	char date[32] = "";
	struct tm tm;

	vt__out_init(out);
	if (!c || !resource) return vt__inval(c, "resource required");
	/* glibc's %Y computes tm_year + 1900 in int: a later year would be
	 * printed as garbage, so it is rejected */
	if (o->date && ((int64_t)t != o->date || !gmtime_r(&t, &tm) ||
	                tm.tm_year > INT_MAX - 1900 ||
	                !strftime(date, sizeof date, "%Y%m%d%H%M%S", &tm)))
		return vt__inval(c, "date out of range");
	const struct vt_param params[] = {
	    VT_P_TEXT("resource", resource),
	    VT_P_TEXT("date", o->date ? date : nullptr),
	    VT_P_INT("period", o->period),
	    VT_P_INT("repeat", o->repeat),
	    VT_P_TEXT("notify_url", o->notify_url),
	    VT_P_TEXT("notify_changes_only",
	              o->notify_url && o->notify_changes_only ? "1" : nullptr),
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "file/rescan",
	    .post = true,
	    .accept = VT_ACCEPT_200,
	    .params = params,
	};
	return vt__perform(c, &rq, out);
}

/* POST file/<path> with "resource", "apikey"; requires HTTP 200. */
static vt_err post_resource(vt_client *c, const char *path,
                            const char *resource, json_t **out) {
	vt__out_init(out);
	if (!c || !resource) return vt__inval(c, "resource required");
	const struct vt_param params[] = {
	    VT_P_TEXT("resource", resource),
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = path,
	    .post = true,
	    .accept = VT_ACCEPT_200,
	    .params = params,
	};
	return vt__perform(c, &rq, out);
}

vt_err vt_file_rescan_delete(vt_client *c, const char *resource, json_t **out) {
	return post_resource(c, "file/rescan/delete", resource, out);
}

vt_err vt_file_report(vt_client *c, const char *resource, json_t **out) {
	return post_resource(c, "file/report", resource, out);
}

vt_err vt_file_search(vt_client *c, const char *query, const char *offset,
                      json_t **out) {
	vt__out_init(out);
	if (!c || !query || !*query) return vt__inval(c, "empty query");
	const struct vt_param params[] = {
	    VT_P_TEXT("query", query),
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_TEXT("offset", offset), /* only when the caller gave one */
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "file/search",
	    .post = true,
	    .accept = VT_ACCEPT_200,
	    .params = params,
	};
	return vt__perform(c, &rq, out);
}

vt_err vt_file_clusters(vt_client *c, const char *date, json_t **out) {
	vt__out_init(out);
	if (!c || !date || !*date) return vt__inval(c, "empty date");
	const struct vt_param params[] = {
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_TEXT("date", date),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "file/clusters",
	    .accept = VT_ACCEPT_200,
	    .params = params,
	};
	return vt__perform(c, &rq, out);
}

vt_err vt_file_download(vt_client *c, const char *hash, vt_write_fn *fn,
                        void *userdata) {
	if (!c || !hash || !*hash || !fn)
		return vt__inval(c, "hash and sink required");
	const struct vt_param params[] = {
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_TEXT("hash", hash),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "file/download",
	    .follow = true,
	    .accept = VT_ACCEPT_200_302,
	    .params = params,
	    .sink = fn,
	    .sink_ud = userdata,
	};
	return vt__perform(c, &rq, nullptr);
}

static size_t to_fp(const void *data, size_t len, void *ud) {
	return fwrite(data, 1, len, ud);
}

vt_err vt_file_download_fp(vt_client *c, const char *hash, FILE *fp) {
	if (!fp) return vt__inval(c, "stream required");
	return vt_file_download(c, hash, to_fp, fp);
}

static size_t to_buf(const void *data, size_t len, void *ud) {
	struct vt_buf *b = ud;

	vt__buf_putn(b, data, len);
	return b->oom ? 0 : len;
}

vt_err vt_file_download_mem(vt_client *c, const char *hash, void **data,
                            size_t *len) {
	struct vt_buf b = {};
	vt_err e;

	if (data) *data = nullptr;
	if (len) *len = 0;
	if (!c || !data || !len) return vt__inval(c, "out-pointers required");
	e = vt_file_download(c, hash, to_buf, &b);
	if (e == VT_ECURL && b.oom)
		e = vt__fail(c, VT_ENOMEM, "download buffer");
	if (!e && !b.data && !(b.data = calloc(1, 1))) /* empty body */
		e = vt__fail(c, VT_ENOMEM, "download buffer");
	if (!e) {
		*data = b.data; /* NUL-terminated, like every vt_buf */
		*len = b.len;
		return VT_OK;
	}
	vt__buf_free(&b);
	return e;
}
