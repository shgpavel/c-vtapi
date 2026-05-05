/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <vt/vt.h>

enum { search_limit = 20 };

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

static vt_status print_results(vt_iter* iter) {
	for (;;) {
		vt_object* object = NULL;
		vt_status status = vt_iter_next(iter, &object);

		if (status != VT_OK) {
			return status;
		}
		if (object == NULL) {
			break;
		}

		printf("%s\t%s\n",
		       vt_object_id(object) != NULL ? vt_object_id(object)
		                                    : "unavailable",
		       vt_object_type(object) != NULL ? vt_object_type(object)
		                                      : "unavailable");
		vt_object_free(object);
	}

	return VT_OK;
}

int main(int argc, char** argv) {
	const char* api_key;
	vt_client* client;
	vt_iter* results = NULL;
	vt_status status;
	int exit_code = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <query>\n", argv[0]);
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

	status = vt_intelligence_search(client, argv[1], search_limit, false,
	                                &results);
	if (status != VT_OK) {
		exit_code =
		    report_status(client, "search intelligence", status);
		goto cleanup;
	}

	status = print_results(results);
	if (status != VT_OK) {
		exit_code = report_status(client, "read search page", status);
	}

cleanup:
	vt_iter_free(results);
	vt_client_free(client);
	return exit_code;
}
