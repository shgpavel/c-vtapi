/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
	const char* api_key = getenv("VTAPI_KEY");

	(void)api_key;
	// TODO(team-lead): expose /search and /intelligence/search in the
	// public v3 client API.
	puts("v3 search is available through the API but not yet exposed here");
	puts("see https://docs.virustotal.com/reference/api-search");
	puts("see https://docs.virustotal.com/reference/intelligence-search");
	return 0;
}
