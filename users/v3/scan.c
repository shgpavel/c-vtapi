/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <vt/vt.h>

enum { poll_attempts = 5 };

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

static void print_verdict_counts(const vt_object* analysis) {
	const char* stats = vt_object_attribute(analysis, "stats");

	if (stats == NULL) {
		stats = vt_object_attribute(analysis, "last_analysis_stats");
	}

	printf("verdict counts: %s\n", stats != NULL ? stats : "unavailable");
}

int main(int argc, char** argv) {
	const char* api_key;
	vt_client* client;
	vt_object* analysis = NULL;
	vt_status status;
	int exit_code = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <path>\n", argv[0]);
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

	status = vt_files_submit_path(client, argv[1], &analysis);
	if (status != VT_OK) {
		exit_code = report_status(client, "submit file", status);
		goto cleanup;
	}

	printf("analysis id: %s\n", vt_object_id(analysis) != NULL
	                                ? vt_object_id(analysis)
	                                : "unavailable");

	for (unsigned int attempt = 0; attempt < poll_attempts; ++attempt) {
		const char* analysis_id = vt_object_id(analysis);
		vt_object* polled = NULL;
		const char* state;

		if (analysis_id == NULL) {
			break;
		}

		status = vt_analyses_get(client, analysis_id, &polled);
		if (status != VT_OK) {
			exit_code =
			    report_status(client, "poll analysis", status);
			goto cleanup;
		}

		vt_object_free(analysis);
		analysis = polled;
		state = vt_object_attribute(analysis, "status");
		if (state != NULL) {
			printf("status: %s\n", state);
		}
		if (vt_object_attribute(analysis, "stats") != NULL) {
			break;
		}
	}

	print_verdict_counts(analysis);

cleanup:
	vt_object_free(analysis);
	vt_client_free(client);
	return exit_code;
}
