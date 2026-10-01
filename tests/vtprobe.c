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
 * vtprobe: library-level driver for the wire-level tests.  It reaches
 * library behaviour that none of the imp/ tools can (file/rescan/delete,
 * the rescan options, notify_url of the scans, vt_file_scan_big() on a
 * small file, the distribution before/after members, cancellation, per
 * call search offsets).  Like the tools it takes the base URL from
 * $VT_API_BASE_URL.  It prints "ret=<legacy code>" lines and Response
 * dumps, which the tests compare with golden files.
 *
 * Usage: vtprobe <cmd> KEY args...     ("-" means NULL for string args)
 *   rescan_delete KEY HASH               vt_file_rescan_delete
 *   rescan KEY HASH DATE PERIOD REPEAT NOTIFY CHANGES_ONLY
 *                       vt_file_rescan; DATE: Unix seconds (0 = none),
 *                       PERIOD/REPEAT: int (0 = omitted), CHANGES_ONLY 0/1
 *   scan KEY PATH NOTIFY                 vt_file_scan
 *   scan_membuf KEY FILENAME DATAFILE NOTIFY
 *                       vt_file_scan_mem with the whole of DATAFILE;
 *                       FILENAME is only the name given to the library
 *   scan_bigfile KEY PATH                vt_file_scan_big
 *   scan_bigfile_cancel_between KEY PATH
 *                       vt_file_scan_big with a vt_cancel() issued by
 *                       jansson's allocator while step 1's response is
 *                       parsed (after its transfer, before the upload)
 *   upload_url KEY                       vt_file_upload_url, prints url=
 *   cancel_report KEY HASH1 HASH2
 *                       vt_cancel() on an idle client, then
 *                       vt_file_report(HASH1) and vt_file_report(HASH2)
 *   search_seq KEY QUERY OFF1 [OFF2 ...]
 *                       one vt_file_search per OFFn: "-" = no offset,
 *                       "@next" = vt_next_offset() of the previous
 *                       response (none if it had none), else the literal
 *   file_dist KEY BEFORE AFTER REPORTS LIMIT N
 *                       N x vt_file_distribution on one query struct
 *   file_dist_nested KEY HASH
 *                       vt_file_distribution whose callback calls
 *                       vt_file_report(HASH); prints the diagnostics after
 *   url_dist KEY BEFORE AFTER ALLINFO LIMIT N
 *                       N x vt_url_distribution on one query struct
 *   url_report KEY RESOURCE SCAN ALLINFO vt_url_report (flags 0/1)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

static const char *S(const char *s) {
	return strcmp(s, "-") ? s : nullptr;
}

/* Prints the outcome of one call and releases *resp. */
static void result(vt_client *c, vt_err e, json_t **resp) {
	printf("ret=%d\n", vtc_legacy(c, e));
	if (!e) vtc_print_response(*resp);
	json_decref(*resp);
	*resp = nullptr;
}

static void fd_cb(const char *url, long long ts, const char *sha,
                  const char *name, json_t *item, void *ud) {
	(void)item, (void)ud;
	printf("cb link=%s ts=%llu sha256=%s name=%s\n", url,
	       (unsigned long long)ts, sha, name ? name : "(null)");
}

static void ud_cb(const char *url, long long ts, long long total, long long pos,
                  json_t *item, void *ud) {
	(void)item, (void)ud;
	printf("cb url=%s ts=%llu total=%d positives=%d\n", url,
	       (unsigned long long)ts, (int)total, (int)pos);
}

struct nested {
	vt_client *c;
	const char *hash;
};

static void nested_cb(const char *url, long long ts, const char *sha,
                      const char *name, json_t *item, void *ud) {
	struct nested *x = ud;
	vt_err e = vt_file_report(x->c, x->hash, nullptr);

	(void)url, (void)ts, (void)sha, (void)name, (void)item;
	printf("nested ret=%d\n", vtc_legacy(x->c, e));
}

/* scan_bigfile_cancel_between: the first jansson allocation after arming
 * calls vt_cancel(). */
static vt_client *cancel_client;
static bool cancel_armed;

static void *cancel_malloc(size_t n) {
	if (cancel_armed) {
		cancel_armed = false;
		vt_cancel(cancel_client);
	}
	return malloc(n);
}

static unsigned char *slurp(const char *path, size_t *len) {
	FILE *fp = fopen(path, "rb");
	unsigned char *buf = nullptr;
	long n;

	*len = 0;
	if (!fp) return nullptr;
	if (!fseek(fp, 0, SEEK_END) && (n = ftell(fp)) >= 0 &&
	    !fseek(fp, 0, SEEK_SET) && (buf = malloc((size_t)n + 1)))
		*len = fread(buf, 1, (size_t)n, fp);
	fclose(fp);
	return buf;
}

static void usage(void) {
	fprintf(stderr,
	        "usage: vtprobe <cmd> KEY args... (see tests/vtprobe.c)\n"
	        "  rescan_delete KEY HASH\n"
	        "  rescan KEY HASH DATE PERIOD REPEAT NOTIFY CHANGES_ONLY\n"
	        "  scan KEY PATH NOTIFY\n"
	        "  scan_membuf KEY FILENAME DATAFILE NOTIFY\n"
	        "  scan_bigfile KEY PATH\n"
	        "  scan_bigfile_cancel_between KEY PATH\n"
	        "  upload_url KEY\n"
	        "  cancel_report KEY HASH1 HASH2\n"
	        "  search_seq KEY QUERY OFF1 [OFF2 ...]\n"
	        "  file_dist KEY BEFORE AFTER REPORTS LIMIT N\n"
	        "  file_dist_nested KEY HASH\n"
	        "  url_dist KEY BEFORE AFTER ALLINFO LIMIT N\n"
	        "  url_report KEY RESOURCE SCAN ALLINFO\n");
}

static void search_seq(vt_client *c, const char *query, char **offs, int n) {
	char *next = nullptr;
	json_t *r;

	for (int i = 0; i < n; i++) {
		const char *off = !strcmp(offs[i], "-")       ? nullptr
		                  : !strcmp(offs[i], "@next") ? next
		                                              : offs[i];
		vt_err e = vt_file_search(c, query, off, &r);

		printf("ret=%d\n", vtc_legacy(c, e));
		free(next);
		next = vt_next_offset(r) ? strdup(vt_next_offset(r)) : nullptr;
		if (!e) {
			json_t *h;
			size_t k;

			json_array_foreach(json_object_get(r, "hashes"), k, h) {
				if (json_is_string(h))
					printf("hash=%s\n",
					       json_string_value(h));
			}
		}
		json_decref(r);
	}
	free(next);
}

static void dist(vt_client *c, bool file, char **a) {
	struct vt_dist_query q = {
	    .before = (long long)strtoull(a[0], nullptr, 10),
	    .after = (long long)strtoull(a[1], nullptr, 10),
	    .limit = atoi(a[3]),
	    .reports = atoi(a[2]) != 0,
	};

	for (int i = atoi(a[4]); i > 0; i--) {
		vt_err e =
		    file ? vt_file_distribution(c, &q, fd_cb, nullptr, nullptr)
		         : vt_url_distribution(c, &q, ud_cb, nullptr, nullptr);

		printf("ret=%d\n", vtc_legacy(c, e));
		if (e) break;
	}
}

int main(int argc, char *argv[]) {
	const char *cmd = argc > 1 ? argv[1] : "";
	char **a = argv + 2;
	int n = argc - 2;
	json_t *r = nullptr;
	vt_client *c;
	vt_err e;

	setvbuf(stdout, nullptr, _IONBF, 0);
	c = vtc_client();
	if (n >= 1 && vt_client_set_apikey(c, a[0])) return 1;

	if (!strcmp(cmd, "rescan_delete") && n == 2) {
		e = vt_file_rescan_delete(c, S(a[1]), &r);
		result(c, e, &r);
	} else if (!strcmp(cmd, "rescan") && n == 7) {
		struct vt_rescan_opts o = {
		    .date = atoll(a[2]),
		    .period = atoi(a[3]),
		    .repeat = atoi(a[4]),
		    .notify_url = S(a[5]),
		    .notify_changes_only = atoi(a[6]) != 0,
		};
		e = vt_file_rescan(c, S(a[1]), &o, &r);
		result(c, e, &r);
	} else if (!strcmp(cmd, "scan") && n == 3) {
		e = vt_file_scan(c, S(a[1]), S(a[2]), &r);
		result(c, e, &r);
	} else if (!strcmp(cmd, "scan_membuf") && n == 4) {
		size_t len;
		unsigned char *buf = slurp(a[2], &len);

		e = vt_file_scan_mem(c, S(a[1]), buf ? buf : (void *)"", len,
		                     S(a[3]), &r);
		result(c, e, &r);
		free(buf);
	} else if (!strcmp(cmd, "scan_bigfile") && n == 2) {
		e = vt_file_scan_big(c, S(a[1]), &r);
		result(c, e, &r);
	} else if (!strcmp(cmd, "scan_bigfile_cancel_between") && n == 2) {
		cancel_client = c;
		cancel_armed = true; /* nothing was allocated by jansson yet */
		json_set_alloc_funcs(cancel_malloc, free);
		e = vt_file_scan_big(c, S(a[1]), &r);
		result(c, e, &r);
	} else if (!strcmp(cmd, "upload_url") && n == 1) {
		char *url;

		e = vt_file_upload_url(c, &url);
		printf("ret=%d\nurl=%s\n", vtc_legacy(c, e),
		       url ? url : "(null)");
		free(url);
	} else if (!strcmp(cmd, "cancel_report") && n == 3) {
		vt_cancel(c); /* must not affect the next operations */
		e = vt_file_report(c, S(a[1]), &r);
		result(c, e, &r);
		e = vt_file_report(c, S(a[2]), &r);
		result(c, e, &r);
	} else if (!strcmp(cmd, "search_seq") && n >= 3) {
		search_seq(c, S(a[1]), a + 2, n - 2);
	} else if ((!strcmp(cmd, "file_dist") || !strcmp(cmd, "url_dist")) &&
	           n == 6) {
		dist(c, cmd[0] == 'f', a + 1);
	} else if (!strcmp(cmd, "file_dist_nested") && n == 2) {
		struct nested x = {.c = c, .hash = a[1]};

		e = vt_file_distribution(c, nullptr, nested_cb, &x, nullptr);
		printf("ret=%d http=%ld curl=%d msg=%s\n", vtc_legacy(c, e),
		       vt_http_status(c), vt_curl_code(c), vt_errmsg(c));
	} else if (!strcmp(cmd, "url_report") && n == 4) {
		unsigned f = (atoi(a[2]) ? VT_URL_REPORT_SCAN : 0u) |
		             (atoi(a[3]) ? VT_URL_REPORT_ALL_INFO : 0u);

		e = vt_url_report(c, S(a[1]), f, &r);
		result(c, e, &r);
	} else {
		usage();
		vt_client_free(c);
		return 2;
	}
	vt_client_free(c);
	return 0;
}
