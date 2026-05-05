/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <vt/vt.h>

static const char* require_api_key(void) {
	const char* api_key = getenv("VTAPI_KEY");

	if (api_key == NULL || api_key[0] == '\0') {
		fprintf(stderr, "VTAPI_KEY is required\n");
		return NULL;
	}

	return api_key;
}

static int report_status(vt_client* client, const char* action,
                         vt_status status) {
	const char* detail = vt_error_last(client);

	fprintf(stderr, "%s: %s", action, vt_status_str(status));
	if (detail != NULL) {
		fprintf(stderr, ": %s", detail);
	}
	fputc('\n', stderr);

	return 1;
}

int main(int argc, char** argv) {
	const char* api_key;
	vt_client* client;
	vt_object* ip = NULL;
	vt_status status;
	int exit_code = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <ip-address>\n", argv[0]);
		return 1;
	}

	api_key = require_api_key();
	if (api_key == NULL) {
		return 1;
	}

	client = vt_client_new(api_key);
	if (client == NULL) {
		fprintf(stderr, "failed to create VirusTotal v3 client\n");
		return 1;
	}

	status = vt_ip_addresses_get(client, argv[1], &ip);
	if (status != VT_OK) {
		exit_code = report_status(client, "get ip address", status);
		goto cleanup;
	}

	printf("id: %s\n",
	       vt_object_id(ip) != NULL ? vt_object_id(ip) : "unavailable");
	printf("last_analysis_stats: %s\n",
	       vt_object_attribute(ip, "last_analysis_stats") != NULL
	           ? vt_object_attribute(ip, "last_analysis_stats")
	           : "unavailable");

cleanup:
	vt_object_free(ip);
	vt_client_free(client);
	return exit_code;
}
