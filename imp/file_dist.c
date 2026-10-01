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

/* file_dist: GET file/distribution, --repeat pages. */

#include <stdio.h>
#include <stdlib.h>

#include "common.h"

static void usage(const char *prog) {
	printf(
	    "%s < --apikey YOUR_API_KEY >  [ --all-info ] [ --sleep X ] "
	    "[ --repeat X ]\n"
	    "  --apikey YOUR_API_KEY  Your virus total API key.  This arg "
	    "1st \n"
	    "  --reports              Get reports\n"
	    "  --before               before timestamp\n"
	    "  --after                before timestamp\n"
	    "  --limit                limit results\n"
	    "  --repeat               Repeat X times updating the feeed\n"
	    "  --sleep                Sleep X seconds between requests\n",
	    prog);
}

static void on_item(const char *link, long long ts, const char *sha256,
                    const char *name, json_t *item, void *ud) {
	int *counter = ud;
	char *s = json_dumps(item, JSON_INDENT(4));

	printf("------------- File %d ----------------\n", ++*counter);
	printf("URL: %s \n", link);
	printf("timestamp: %lld\n", ts);
	printf("name: %s\n", name ? name : "(null)");
	printf("sha256: %s\n", sha256);
	printf("%s \n", s ? s : "");
	free(s);
	printf("\n");
}

static vt_err fetch(vt_client *c, struct vt_dist_query *q, int *counter) {
	return vt_file_distribution(c, q, on_item, counter, nullptr);
}

int main(int argc, char *argv[]) {
	return vtc_dist_main(argc, argv, usage, "reports", fetch);
}
