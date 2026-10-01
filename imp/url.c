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

/* url: POST url/scan and url/report. */

#include <stdio.h>

#include "common.h"

static void usage(const char *prog) {
	printf(
	    "%s < --apikey YOUR_API_KEY >  [ --all-info ] [ --report-scan ]"
	    "  [ --report URL ] [ --scan URL ]\n"
	    "  --apikey YOUR_API_KEY   Your virus total API key.  This arg "
	    "1st \n"
	    "  --all-info              When doing a report, set allinfo "
	    "flag\n"
	    "  --report-scan           When doing a report, set scan flag\n"
	    "  --scan URL              URL to scan. \n"
	    "  --report URL            URL to report.\n",
	    prog);
}

struct ctx {
	struct vtc_tool t;
	unsigned flags; /* sticky --report-scan / --all-info */
};

static enum vtc_act on_opt(int ch, const char *arg, void *ctxp) {
	struct ctx *x = ctxp;
	json_t *resp = nullptr;
	vt_err e;

	switch (ch) {
		case 's':
			vtc_require(x->t.have_key, "apikey");
			e = vt_url_scan(x->t.c, arg, &resp);
			break;
		case 'r':
			vtc_require(x->t.have_key, "apikey");
			e = vt_url_report(x->t.c, arg, x->flags, &resp);
			break;
		case '1':
			x->flags |= VT_URL_REPORT_SCAN;
			return VTC_NEXT;
		case 'i':
			x->flags |= VT_URL_REPORT_ALL_INFO;
			return VTC_NEXT;
		case 'h':
			usage(x->t.prog);
			return VTC_STOP;
		default:
			return VTC_UNKNOWN;
	}
	vtc_print_result(x->t.c, e, resp);
	json_decref(resp);
	return VTC_NEXT;
}

int main(int argc, char *argv[]) {
	static const struct option opts[] = {
	    {"scan", required_argument, nullptr, 's'},
	    {"report", required_argument, nullptr, 'r'},
	    {"apikey", required_argument, nullptr, 'a'},
	    {"report-scan", no_argument, nullptr, '1'},
	    {"all-info", no_argument, nullptr, 'i'},
	    {"verbose", optional_argument, nullptr, 'v'},
	    {"help", optional_argument, nullptr, 'h'},
	    {},
	};
	struct ctx x = {.t.echo_key = true};

	if (!vtc_start(&x.t, argc, argv, usage)) return 0;
	vtc_getopt(&x.t, argc, argv, opts, on_opt, &x);
	vt_client_free(x.t.c);
	return 0;
}
