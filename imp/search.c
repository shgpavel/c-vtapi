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

/* search: POST file/search, --repeat pages following the returned
 * offset. */

#include <stdio.h>
#include <stdlib.h>

#include "common.h"

static void usage(const char *prog) {
	printf(
	    "%s < --apikey YOUR_API_KEY >  [ --query 'QUERY STRING' ] "
	    "[ --offset X ]\n"
	    "  --apikey YOUR_API_KEY   Your virus total API key.  This arg "
	    "1st \n"
	    "  --query             'Query String'\n"
	    "  --offset             Offset Value\n",
	    prog);
}

struct ctx {
	struct vtc_tool t;
	char *query, *offset;
	int repeat;
};

static enum vtc_act on_opt(int ch, const char *arg, void *ctxp) {
	struct ctx *x = ctxp;

	switch (ch) {
		case 'q':
			vtc_strset(&x->query, arg);
			return VTC_NEXT;
		case 'r':
			x->repeat = atoi(arg);
			return VTC_NEXT;
		case 'o':
			vtc_strset(&x->offset, arg);
			return VTC_NEXT;
		case 'h':
			usage(x->t.prog);
			return VTC_STOP;
		default:
			return VTC_UNKNOWN;
	}
}

int main(int argc, char *argv[]) {
	static const struct option opts[] = {
	    {"apikey", required_argument, nullptr, 'a'},
	    {"query", required_argument, nullptr, 'q'},
	    {"repeat", required_argument, nullptr, 'r'},
	    {"offset", required_argument, nullptr, 'o'},
	    {"verbose", optional_argument, nullptr, 'v'},
	    {"help", optional_argument, nullptr, 'h'},
	    {},
	};
	struct ctx x = {.repeat = 1};
	int counter = 0;

	if (!vtc_start(&x.t, argc, argv, usage)) return 0;
	if (vtc_getopt(&x.t, argc, argv, opts, on_opt, &x) >= 0) {
		for (; x.repeat > 0; x.repeat--) {
			json_t *resp, *h;
			size_t i;
			vt_err e;

			printf("Repeating %d times\n", x.repeat);
			e = vt_file_search(x.t.c, x.query, x.offset, &resp);
			if (e) {
				printf("returned error %d\n",
				       vtc_legacy(x.t.c, e));
				break;
			}
			/* the next page starts at the returned offset; none
			 * means the next request sends no offset */
			vtc_strset(&x.offset, vt_next_offset(resp));
			json_array_foreach(json_object_get(resp, "hashes"), i,
			                   h) {
				if (!json_is_string(h)) continue;
				printf(
				    "------------- Result %d "
				    "----------------\n",
				    ++counter);
				printf("resource: %s \n", json_string_value(h));
				printf("\n");
			}
			json_decref(resp);
		}
	}
	vt_client_free(x.t.c);
	free(x.query);
	free(x.offset);
	return 0;
}
