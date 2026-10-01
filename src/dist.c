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

/* file/distribution and url/distribution: fetch one page, validate each
 * element in order, advance q->after, call back (as the old library). */

#include <stdlib.h>

#include "private.h"

/* GET <path>?apikey=K[&before=B][&after=A][&<flag>=true][&limit=L] */
static vt_err fetch(vt_client *c, const char *path, const char *flag,
                    const struct vt_dist_query *q, json_t **root) {
	const struct vt_param params[] = {
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_INT("before", q->before),
	    VT_P_INT("after", q->after),
	    VT_P_TEXT(flag, q->reports ? "true" : nullptr),
	    VT_P_INT("limit", q->limit),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = path,
	    .accept = VT_ACCEPT_200,
	    .params = params,
	};
	return vt__perform(c, &rq, root);
}

/*
 * Ends a walk that started with a page fetched with HTTP `status`: hands
 * root to the caller or drops it and returns `e`.  The callbacks may have
 * run other operations on c, so the diagnostics are rebuilt to describe
 * this call: its status, no CURLcode, and the walk's own message (set by
 * vt__fail() after any nested operation) or none.
 */
static vt_err finish(vt_client *c, vt_err e, long status, json_t *root,
                     json_t **out) {
	c->http_status = status;
	c->curl_code = 0;
	if (!e) {
		free(c->msg);
		c->msg = nullptr;
	}
	c->last = e;
	if (!e && out)
		*out = root;
	else
		json_decref(root);
	return e;
}

vt_err vt_file_distribution(vt_client *c, struct vt_dist_query *q,
                            vt_file_dist_fn *fn, void *ud, json_t **out) {
	struct vt_dist_query none = {};
	json_t *root, *el;
	long status;
	size_t i;
	vt_err e;

	vt__out_init(out);
	if (!c) return VT_EINVAL;
	if (!q) q = &none;
	if ((e = fetch(c, "file/distribution", "reports", q, &root))) return e;
	status = c->http_status;
	if (!json_is_array(root)) {
		e = vt__fail(c, VT_EPROTO, "JSON is not array");
		return finish(c, e, status, root, out);
	}
	json_array_foreach(root, i, el) {
		json_t *link = json_object_get(el, "link");
		json_t *name = json_object_get(el, "name");
		json_t *sha = json_object_get(el, "sha256");
		json_t *ts = json_object_get(el, "timestamp");

		if (!json_is_object(el) || !json_is_string(link) ||
		    !json_is_string(sha) || !json_is_integer(ts)) {
			e = vt__fail(c, VT_EPROTO, "element %zu malformed", i);
			return finish(c, e, status, root, out);
		}
		q->after = json_integer_value(ts);
		if (fn)
			fn(json_string_value(link), q->after,
			   json_string_value(sha), json_string_value(name), el,
			   ud);
	}
	return finish(c, VT_OK, status, root, out);
}

vt_err vt_url_distribution(vt_client *c, struct vt_dist_query *q,
                           vt_url_dist_fn *fn, void *ud, json_t **out) {
	struct vt_dist_query none = {};
	json_t *root, *el;
	long status;
	size_t i;
	vt_err e;

	vt__out_init(out);
	if (!c) return VT_EINVAL;
	if (!q) q = &none;
	if ((e = fetch(c, "url/distribution", "allinfo", q, &root))) return e;
	status = c->http_status;
	if (!json_is_array(root)) {
		e = vt__fail(c, VT_EPROTO, "JSON is not array");
		return finish(c, e, status, root, out);
	}
	json_array_foreach(root, i, el) {
		json_t *url = json_object_get(el, "url");
		json_t *ts = json_object_get(el, "timestamp");
		json_t *tot = json_object_get(el, "total");
		json_t *pos = json_object_get(el, "positives");

		if (!json_is_object(el) || !json_is_string(url) ||
		    !json_is_integer(ts) || !json_is_integer(tot) ||
		    !json_is_integer(pos)) {
			e = vt__fail(c, VT_EPROTO, "element %zu malformed", i);
			return finish(c, e, status, root, out);
		}
		q->after = json_integer_value(ts);
		if (fn)
			fn(json_string_value(url), q->after,
			   json_integer_value(tot), json_integer_value(pos), el,
			   ud);
	}
	return finish(c, VT_OK, status, root, out);
}
