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

/* comments: POST comments/put, GET comments/get. */

#include <stdio.h>
#include <stdlib.h>

#include "common.h"

static void usage(const char *prog) {
	printf(
	    "%s < --apikey YOUR_API_KEY >  [ --resource ] [ --get ]  "
	    "[ --put \"<comments>\" ] < --before YYYYMMDDHHSS >\n"
	    "  --apikey YOUR_API_KEY   Your virus total API key.  This arg "
	    "1st \n"
	    "  --resource              Hash your looking for\n"
	    "  --get                   Get commnets of resource\n"
	    "  --put 'comments'        'comments' to add to resource\n"
	    "  --before 'YYYYMMDDHHSS'  datetime token\n",
	    prog);
}

struct ctx {
	struct vtc_tool t;
	char *resource, *before;
	bool get;
};

static enum vtc_act on_opt(int ch, const char *arg, void *ctxp) {
	struct ctx *x = ctxp;

	switch (ch) {
		case 'r':
			printf(" resource: %s \n", arg);
			vtc_strset(&x->resource, arg);
			return VTC_NEXT;
		case 'b':
			printf(" before: %s \n", arg);
			vtc_strset(&x->before, arg);
			return VTC_NEXT;
		case 'p': /* legacy: the result is ignored, nothing printed */
			x->get = false;
			(void)vt_comments_put(x->t.c, x->resource, arg,
			                      nullptr);
			return VTC_NEXT;
		case 'h':
			usage(x->t.prog);
			return VTC_STOP;
		default: /* includes 'g': --get never had a handler */
			return VTC_UNKNOWN;
	}
}

int main(int argc, char *argv[]) {
	static const struct option opts[] = {
	    {"apikey", required_argument, nullptr, 'a'},
	    {"before", required_argument, nullptr, 'b'},
	    {"put", required_argument, nullptr, 'p'},
	    {"resource", required_argument, nullptr, 'r'},
	    {"get", no_argument, nullptr, 'g'},
	    {"verbose", optional_argument, nullptr, 'v'},
	    {"help", optional_argument, nullptr, 'h'},
	    {},
	};
	struct ctx x = {.t.echo_key = true, .get = true};
	int n;

	if (!vtc_start(&x.t, argc, argv, usage)) return 0;
	n = vtc_getopt(&x.t, argc, argv, opts, on_opt, &x);
	/* legacy: non-option arguments skip the retrieval */
	if (n == 0 && x.get) {
		json_t *resp = nullptr;
		vt_err e = vt_comments_get(x.t.c, x.resource, x.before, &resp);

		vtc_print_result(x.t.c, e, resp);
		json_decref(resp);
	}
	vt_client_free(x.t.c);
	free(x.resource);
	free(x.before);
	return 0;
}
