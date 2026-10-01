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

/* url/..., ip-address/report, domain/report, comments/...: like the old
 * library, any HTTP status is accepted and the body must be JSON. */

#include "private.h"

vt_err vt_url_scan(vt_client *c, const char *url, json_t **out) {
	vt__out_init(out);
	if (!c || !url) return vt__inval(c, "url required");
	const struct vt_param params[] = {
	    VT_P_TEXT("url", url),
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "url/scan",
	    .post = true,
	    .params = params,
	};
	return vt__perform(c, &rq, out);
}

vt_err vt_url_report(vt_client *c, const char *resource, unsigned flags,
                     json_t **out) {
	const unsigned known = VT_URL_REPORT_SCAN | VT_URL_REPORT_ALL_INFO;

	vt__out_init(out);
	if (!c || !resource || (flags & ~known))
		return vt__inval(c, "resource required / bad flags");
	const struct vt_param params[] = {
	    VT_P_TEXT("resource", resource),
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_TEXT("scan", flags & VT_URL_REPORT_SCAN ? "1" : nullptr),
	    /* the field name the old library used, kept as is */
	    VT_P_TEXT("all_info",
	              flags & VT_URL_REPORT_ALL_INFO ? "1" : nullptr),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "url/report",
	    .post = true,
	    .params = params,
	};
	return vt__perform(c, &rq, out);
}

/* GET <path>?apikey=K&<name>=<value> */
static vt_err get_report(vt_client *c, const char *path, const char *name,
                         const char *value, json_t **out) {
	vt__out_init(out);
	if (!c || !value) return vt__inval(c, "%s required", name);
	const struct vt_param params[] = {
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_TEXT(name, value),
	    VT_P_END,
	};
	const struct vt_req rq = {.path = path, .params = params};
	return vt__perform(c, &rq, out);
}

vt_err vt_ip_report(vt_client *c, const char *ip, json_t **out) {
	return get_report(c, "ip-address/report", "ip", ip, out);
}

vt_err vt_domain_report(vt_client *c, const char *domain, json_t **out) {
	return get_report(c, "domain/report", "domain", domain, out);
}

vt_err vt_comments_put(vt_client *c, const char *resource, const char *comment,
                       json_t **out) {
	vt__out_init(out);
	if (!c || !resource || !comment)
		return vt__inval(c, "resource and comment required");
	const struct vt_param params[] = {
	    VT_P_TEXT("resource", resource),
	    VT_P_TEXT("comment", comment),
	    VT_P_TEXT("apikey", vt__key(c)),
	    VT_P_END,
	};
	const struct vt_req rq = {
	    .path = "comments/put",
	    .post = true,
	    .params = params,
	};
	return vt__perform(c, &rq, out);
}

vt_err vt_comments_get(vt_client *c, const char *resource, const char *before,
                       json_t **out) {
	vt__out_init(out);
	if (!c || !resource || !c->apikey)
		return vt__inval(c, "resource and API key required");
	const struct vt_param params[] = {
	    VT_P_TEXT("apikey", c->apikey),
	    VT_P_TEXT("resource", resource),
	    VT_P_TEXT("before", before), /* "" is sent */
	    VT_P_END,
	};
	const struct vt_req rq = {.path = "comments/get", .params = params};
	return vt__perform(c, &rq, out);
}
