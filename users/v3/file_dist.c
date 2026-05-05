/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
	const char* api_key = getenv("VTAPI_KEY");

	(void)api_key;
	// TODO(team-lead): expose /feeds/files in the public v3 client API.
	puts("file distribution moved to v3 file feeds");
	puts("see https://docs.virustotal.com/reference/feeds-file");
	return 0;
}
