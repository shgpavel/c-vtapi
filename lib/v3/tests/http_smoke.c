/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../http.h"

int main(void) {
	const char* enabled = getenv("VTAPI_HTTP_NETWORK");
	if (enabled == NULL || strcmp(enabled, "1") != 0) {
		return 77;
	}

	vt_client* client = vt_client_new("test-key");
	if (client == NULL) {
		fputs("failed to create client\n", stderr);
		return 1;
	}

	if (vt_client_set_base_url(client, "https://httpbin.org") != VT_OK) {
		fprintf(stderr, "%s\n", vt_error_last(client));
		vt_client_free(client);
		return 1;
	}

	vt_http_request request = {
	    .method = VT_HTTP_GET,
	    .path = "/get",
	};
	vt_http_response response = {0};
	const vt_status status =
	    vt_http_send_default(client, &request, &response);
	if (status != VT_OK || response.status_code != 200) {
		fprintf(
		    stderr, "HTTP smoke failed: %s (%ld) %s\n",
		    vt_status_str(status), response.status_code,
		    vt_error_last(client) == NULL ? "" : vt_error_last(client));
		vt_http_response_cleanup(&response);
		vt_client_free(client);
		return 1;
	}

	vt_http_response_cleanup(&response);
	vt_client_free(client);
	return 0;
}
