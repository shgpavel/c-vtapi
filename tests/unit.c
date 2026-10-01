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
 * Unit tests of the public API that need no network: error strings, the
 * version, the JSON helpers and argument validation.  The client points
 * at http://127.0.0.1:1/ so that a request sent by mistake fails fast;
 * every VT_EINVAL case also checks that no transfer was attempted
 * (vt_curl_code() == 0) and that *out was reset.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vt/vt.h"

static int failures, checks;

#define CHECK(cond)                                                            \
	do {                                                                   \
		checks++;                                                      \
		if (!(cond)) {                                                 \
			failures++;                                            \
			fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, \
			        __LINE__, #cond);                              \
		}                                                              \
	} while (0)

/* A pointer that is neither NULL nor a valid json_t: *out must be reset
 * before anything else happens. */
#define POISON ((json_t *)(uintptr_t)0x1)

static void test_strerror(void) {
	static const vt_err all[] = {
	    VT_OK,    VT_EINVAL, VT_ENOMEM,  VT_ECURL, VT_EHTTP,
	    VT_EJSON, VT_EPROTO, VT_ECANCEL, VT_EIO,
	};
	const size_t n = sizeof all / sizeof all[0];

	for (size_t i = 0; i < n; i++) {
		const char *s = vt_strerror(all[i]);

		CHECK(s != nullptr && *s);
		CHECK(strcmp(s, "unknown error") != 0);
		for (size_t j = 0; j < i; j++)
			CHECK(strcmp(s, vt_strerror(all[j])) != 0);
	}
	CHECK(!strcmp(vt_strerror(VT_OK), "no error"));
	CHECK(!strcmp(vt_strerror((vt_err)(VT_EIO + 1)), "unknown error"));
	CHECK(!strcmp(vt_strerror((vt_err)-1), "unknown error"));
}

static void test_version(void) {
	CHECK(vt_version() == (unsigned)VT_VERSION_NUM);
	CHECK(VT_VERSION_NUM == ((VT_VERSION_MAJOR << 16) |
	                         (VT_VERSION_MINOR << 8) | VT_VERSION_PATCH));
}

static json_t *parse(const char *s) {
	json_t *j = json_loads(s, 0, nullptr);

	CHECK(j != nullptr);
	return j;
}

static void test_json_helpers(void) {
	json_t *ok = parse(
	    "{\"response_code\": 1, \"verbose_msg\": \"hi\","
	    " \"offset\": \"next\"}");
	json_t *neg = parse("{\"response_code\": -2}");
	json_t *str = parse(
	    "{\"response_code\": \"1\", \"verbose_msg\": 5,"
	    " \"offset\": 7}");
	json_t *empty = parse("{\"verbose_msg\": \"\", \"offset\": \"\"}");
	json_t *null = parse("{\"verbose_msg\": null, \"offset\": null}");
	json_t *arr = parse("[{\"response_code\": 1}]");
	int code;

	code = 42;
	CHECK(vt_response_code(ok, &code) && code == 1);
	CHECK(vt_response_code(neg, &code) && code == -2);
	code = 42;
	CHECK(vt_response_code(str, &code) && code == 0); /* non-integer */
	code = 42;
	CHECK(!vt_response_code(empty, &code) && code == 42);
	CHECK(!vt_response_code(arr, &code) && code == 42);
	CHECK(!vt_response_code(nullptr, &code) && code == 42);
	CHECK(!vt_response_code(ok, nullptr));

	CHECK(vt_verbose_msg(ok) && !strcmp(vt_verbose_msg(ok), "hi"));
	CHECK(vt_verbose_msg(str) == nullptr);
	CHECK(vt_verbose_msg(empty) == nullptr);
	CHECK(vt_verbose_msg(null) == nullptr);
	CHECK(vt_verbose_msg(arr) == nullptr);
	CHECK(vt_verbose_msg(nullptr) == nullptr);

	CHECK(vt_next_offset(ok) && !strcmp(vt_next_offset(ok), "next"));
	CHECK(vt_next_offset(str) == nullptr);
	CHECK(vt_next_offset(empty) == nullptr);
	CHECK(vt_next_offset(null) == nullptr);
	CHECK(vt_next_offset(arr) == nullptr);
	CHECK(vt_next_offset(nullptr) == nullptr);

	json_decref(ok);
	json_decref(neg);
	json_decref(str);
	json_decref(empty);
	json_decref(null);
	json_decref(arr);
}

/* The last operation on c failed with VT_EINVAL before any transfer. */
static bool inval(const vt_client *c, vt_err e) {
	return e == VT_EINVAL && vt_http_status(c) == 0 &&
	       vt_curl_code(c) == 0 && vt_errmsg(c) && *vt_errmsg(c);
}

static void test_null_client(void) {
	struct vt_dist_query q = {};
	json_t *out = POISON;
	char byte = 0, *url = &byte;
	void *data = &q;
	size_t len = 1;

	CHECK(vt_http_status(nullptr) == 0);
	CHECK(vt_curl_code(nullptr) == 0);
	CHECK(vt_errmsg(nullptr) && *vt_errmsg(nullptr));
	vt_cancel(nullptr);
	vt_client_free(nullptr);
	vt_client_set_progress(nullptr, nullptr, nullptr);
	CHECK(vt_client_set_apikey(nullptr, "k") == VT_EINVAL);

#define NULL_CLIENT(call)                   \
	do {                                \
		out = POISON;               \
		CHECK((call) == VT_EINVAL); \
		CHECK(out == nullptr);      \
	} while (0)
	NULL_CLIENT(vt_file_scan(nullptr, "p", nullptr, &out));
	NULL_CLIENT(vt_file_scan_mem(nullptr, "f", "", 0, nullptr, &out));
	NULL_CLIENT(vt_file_scan_big(nullptr, "p", &out));
	NULL_CLIENT(vt_file_rescan(nullptr, "h", nullptr, &out));
	NULL_CLIENT(vt_file_rescan_delete(nullptr, "h", &out));
	NULL_CLIENT(vt_file_report(nullptr, "h", &out));
	NULL_CLIENT(vt_file_search(nullptr, "q", nullptr, &out));
	NULL_CLIENT(vt_file_clusters(nullptr, "2024-01-01", &out));
	NULL_CLIENT(vt_url_scan(nullptr, "u", &out));
	NULL_CLIENT(vt_url_report(nullptr, "u", 0, &out));
	NULL_CLIENT(vt_ip_report(nullptr, "1.2.3.4", &out));
	NULL_CLIENT(vt_domain_report(nullptr, "example.com", &out));
	NULL_CLIENT(vt_comments_put(nullptr, "h", "c", &out));
	NULL_CLIENT(vt_comments_get(nullptr, "h", nullptr, &out));
	NULL_CLIENT(vt_file_distribution(nullptr, &q, nullptr, nullptr, &out));
	NULL_CLIENT(vt_url_distribution(nullptr, &q, nullptr, nullptr, &out));
#undef NULL_CLIENT
	CHECK(vt_file_upload_url(nullptr, &url) == VT_EINVAL && !url);
	CHECK(vt_file_download_mem(nullptr, "h", &data, &len) == VT_EINVAL);
	CHECK(data == nullptr && len == 0);
	CHECK(vt_file_download_fp(nullptr, "h", stdout) == VT_EINVAL);
}

static size_t sink(const void *data, size_t len, void *ud) {
	(void)data, (void)ud;
	return len;
}

static void test_invalid_args(void) {
	vt_client *c = vt_client_new(nullptr, "http://127.0.0.1:1/");
	vt_client *k = vt_client_new("key", "http://127.0.0.1:1/");
	struct vt_rescan_opts far = {.date = INT64_MAX};
	char byte = 0;
	json_t *out;
	void *data;
	size_t len;

	CHECK(c != nullptr && k != nullptr);
	if (!c || !k) return;
	CHECK(vt_http_status(c) == 0 && vt_curl_code(c) == 0);
	CHECK(!strcmp(vt_errmsg(c), vt_strerror(VT_OK)));

#define INVAL(cl, call)                   \
	do {                              \
		out = POISON;             \
		CHECK(inval(cl, (call))); \
		CHECK(out == nullptr);    \
	} while (0)
	INVAL(k, vt_file_scan(k, nullptr, nullptr, &out));
	INVAL(k, vt_file_scan(k, "", nullptr, &out));
	INVAL(k, vt_file_scan_mem(k, nullptr, &byte, 1, nullptr, &out));
	INVAL(k, vt_file_scan_mem(k, "", &byte, 1, nullptr, &out));
	INVAL(k, vt_file_scan_mem(k, "f", nullptr, 1, nullptr, &out));
	/* validated before the buffer is read */
	INVAL(k, vt_file_scan_mem(k, "f", &byte, (size_t)32 * 1024 * 1024,
	                          nullptr, &out));
	INVAL(k, vt_file_scan_big(k, nullptr, &out));
	INVAL(k, vt_file_scan_big(k, "", &out));
	INVAL(k, vt_file_rescan(k, nullptr, nullptr, &out));
	INVAL(k, vt_file_rescan(k, "h", &far, &out)); /* not a UTC time */
	INVAL(k, vt_file_rescan_delete(k, nullptr, &out));
	INVAL(k, vt_file_report(k, nullptr, &out));
	INVAL(k, vt_file_search(k, nullptr, nullptr, &out));
	INVAL(k, vt_file_search(k, "", "offset", &out));
	INVAL(k, vt_file_clusters(k, nullptr, &out));
	INVAL(k, vt_file_clusters(k, "", &out));
	INVAL(k, vt_url_scan(k, nullptr, &out));
	INVAL(k, vt_url_report(k, nullptr, 0, &out));
	INVAL(k, vt_url_report(k, "u", 1u << 2, &out)); /* unknown flag */
	INVAL(k, vt_ip_report(k, nullptr, &out));
	INVAL(k, vt_domain_report(k, nullptr, &out));
	INVAL(k, vt_comments_put(k, nullptr, "c", &out));
	INVAL(k, vt_comments_put(k, "h", nullptr, &out));
	INVAL(k, vt_comments_get(k, nullptr, nullptr, &out));
	INVAL(c, vt_comments_get(c, "h", nullptr, &out)); /* no API key */
#undef INVAL

	CHECK(inval(k, vt_file_upload_url(k, nullptr)));
	CHECK(inval(k, vt_file_download(k, nullptr, sink, nullptr)));
	CHECK(inval(k, vt_file_download(k, "", sink, nullptr)));
	CHECK(inval(k, vt_file_download(k, "h", nullptr, nullptr)));
	CHECK(inval(k, vt_file_download_fp(k, "h", nullptr)));
	CHECK(inval(k, vt_file_download_fp(k, "", stdout)));
	data = &byte;
	len = 1;
	CHECK(inval(k, vt_file_download_mem(k, "", &data, &len)));
	CHECK(data == nullptr && len == 0);
	CHECK(inval(k, vt_file_download_mem(k, "h", nullptr, &len)));
	CHECK(inval(k, vt_file_download_mem(k, "h", &data, nullptr)));

	/* the key can be replaced and cleared */
	CHECK(vt_client_set_apikey(c, "key") == VT_OK);
	CHECK(vt_client_set_apikey(c, nullptr) == VT_OK);
	out = POISON;
	CHECK(inval(c, vt_comments_get(c, "h", nullptr, &out)));
	CHECK(out == nullptr);

	vt_client_free(c);
	vt_client_free(k);
}

int main(void) {
	vt_set_debug(0);
	test_strerror();
	test_version();
	test_json_helpers();
	test_null_client();
	test_invalid_args();
	printf("%d checks, %d failed\n", checks, failures);
	return failures ? 1 : 0;
}
