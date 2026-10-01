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

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void oom(void) {
	fprintf(stderr, "out of memory\n");
	exit(1);
}

vt_client *vtc_client(void) {
	vt_client *c;

	c = vt_client_new(nullptr, getenv("VT_API_BASE_URL"));
	if (!c) oom();
	return c;
}

int vtc_legacy(const vt_client *c, vt_err e) {
	switch (e) {
		case VT_OK:
			return 0;
		case VT_EHTTP:
			return (int)vt_http_status(c);
		case VT_ECURL:
		case VT_ECANCEL:
		case VT_EIO:
			return vt_curl_code(c);
		case VT_EINVAL:
		case VT_ENOMEM:
		case VT_EJSON:
		case VT_EPROTO:
			break;
	}
	return -1;
}

void vtc_print_response(const json_t *resp) {
	char *s = resp ? json_dumps(resp, JSON_INDENT(4)) : nullptr;

	if (s) printf("Response:\n%s\n", s);
	free(s);
}

void vtc_print_result(const vt_client *c, vt_err e, const json_t *resp) {
	if (e)
		printf("Error: %d \n", vtc_legacy(c, e));
	else
		vtc_print_response(resp);
}

void vtc_require(bool ok, const char *what) {
	if (ok) return;
	printf("Must set --%s first\n", what);
	exit(1);
}

void vtc_strset(char **dst, const char *v) {
	free(*dst);
	*dst = nullptr;
	if (v && !(*dst = strdup(v))) oom();
}

bool vtc_start(struct vtc_tool *t, int argc, char *argv[],
               vtc_usage_fn *usage) {
	if (argc < 2) {
		usage(argv[0]);
		return false;
	}
	t->prog = argv[0];
	t->c = vtc_client();
	return true;
}

int vtc_getopt(struct vtc_tool *t, int argc, char *const argv[],
               const struct option *opts, vtc_opt_fn *fn, void *ctx) {
	int ch, idx, n;

	while ((ch = getopt_long_only(argc, argv, "", opts, &idx)) != -1) {
		enum vtc_act a = VTC_NEXT;

		if (ch == 'a') {
			t->have_key = true;
			if (t->echo_key) printf(" apikey: %s \n", optarg);
			if (vt_client_set_apikey(t->c, optarg)) oom();
		} else if (ch == 'v') {
			printf(" verbose selected\n");
			if (optarg) printf(" verbose level %s \n", optarg);
		} else {
			a = fn(ch, optarg, ctx);
		}
		if (a == VTC_STOP) return -1;
		if (a == VTC_UNKNOWN)
			printf("?? getopt returned character code 0%o ??\n",
			       (unsigned)ch);
	}
	n = argc - optind;
	if (n > 0) {
		printf("non-option ARGV-elements: ");
		while (optind < argc) printf("%s ", argv[optind++]);
		printf("\n");
	}
	return n;
}

/* ---- ip / domain_report ---- */

struct report_ctx {
	struct vtc_tool t;
	vtc_usage_fn *usage;
	vtc_report_fn *fn;
};

static enum vtc_act report_opt(int ch, const char *arg, void *ctx) {
	struct report_ctx *x = ctx;
	json_t *resp = nullptr;
	vt_err e;

	switch (ch) {
		case 'r':
			vtc_require(x->t.have_key, "apikey");
			e = x->fn(x->t.c, arg, &resp);
			vtc_print_result(x->t.c, e, resp);
			json_decref(resp);
			return VTC_NEXT;
		case 'h':
			x->usage(x->t.prog); /* and keeps parsing */
			return VTC_NEXT;
		default:
			return VTC_UNKNOWN;
	}
}

int vtc_report_main(int argc, char *argv[], vtc_usage_fn *usage,
                    vtc_report_fn *fn) {
	static const struct option opts[] = {
	    {"report", required_argument, nullptr, 'r'},
	    {"apikey", required_argument, nullptr, 'a'},
	    {"verbose", optional_argument, nullptr, 'v'},
	    {"help", optional_argument, nullptr, 'h'},
	    {},
	};
	struct report_ctx x = {.t.echo_key = true, .usage = usage, .fn = fn};

	if (!vtc_start(&x.t, argc, argv, usage)) return 0;
	vtc_getopt(&x.t, argc, argv, opts, report_opt, &x);
	vt_client_free(x.t.c);
	return 0;
}

/* ---- file_dist / url_dist ---- */

struct dist_ctx {
	struct vtc_tool t;
	vtc_usage_fn *usage;
	struct vt_dist_query q;
	int repeat, sleep_sec;
};

static enum vtc_act dist_opt(int ch, const char *arg, void *ctx) {
	struct dist_ctx *x = ctx;

	switch (ch) {
		case 'l':
			x->q.limit = atoi(arg);
			return VTC_NEXT;
		case 'i':
			x->q.reports = atoi(arg) != 0;
			return VTC_NEXT;
		case 'r':
			x->repeat = atoi(arg);
			return VTC_NEXT;
		case 's':
			x->sleep_sec = atoi(arg);
			return VTC_NEXT;
		case 'h':
			x->usage(x->t.prog);
			return VTC_STOP;
		default: /* --before/--after were never implemented */
			return VTC_UNKNOWN;
	}
}

int vtc_dist_main(int argc, char *argv[], vtc_usage_fn *usage, const char *flag,
                  vtc_dist_fn *fetch) {
	const struct option opts[] = {
	    {"apikey", required_argument, nullptr, 'a'},
	    {"before", required_argument, nullptr, 'b'},
	    {"after", required_argument, nullptr, 'f'},
	    {"limit", required_argument, nullptr, 'l'},
	    {flag, required_argument, nullptr, 'i'},
	    {"repeat", required_argument, nullptr, 'r'},
	    {"sleep", required_argument, nullptr, 's'},
	    {"verbose", optional_argument, nullptr, 'v'},
	    {"help", optional_argument, nullptr, 'h'},
	    {},
	};
	struct dist_ctx x = {.usage = usage, .repeat = 3, .sleep_sec = 3};
	int counter = 0;

	if (!vtc_start(&x.t, argc, argv, usage)) return 0;
	if (vtc_getopt(&x.t, argc, argv, opts, dist_opt, &x) >= 0) {
		for (; x.repeat; x.repeat--) {
			vt_err e;

			printf("\n%d requests remaining\n", x.repeat);
			e = fetch(x.t.c, &x.q, &counter);
			if (e) {
				printf("returned error %d\n",
				       vtc_legacy(x.t.c, e));
				break;
			}
			if (x.repeat > 1) sleep((unsigned)x.sleep_sec);
		}
	}
	vt_client_free(x.t.c);
	return 0;
}
