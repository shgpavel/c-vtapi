/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <vt/vt.h>

enum { comment_limit = 10 };

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

static vt_status list_comments(vt_iter* iter) {
	for (unsigned int count = 0; count < comment_limit; ++count) {
		vt_object* comment = NULL;
		vt_status status = vt_iter_next(iter, &comment);

		if (status != VT_OK) {
			return status;
		}
		if (comment == NULL) {
			break;
		}

		printf("comment %s: %s\n",
		       vt_object_id(comment) != NULL ? vt_object_id(comment)
		                                     : "unavailable",
		       vt_object_attribute(comment, "text") != NULL
		           ? vt_object_attribute(comment, "text")
		           : "unavailable");
		vt_object_free(comment);
	}

	return VT_OK;
}

static int add_comment(vt_client* client, const char* file_id,
                       const char* text) {
	(void)client;
	(void)file_id;
	(void)text;

	// TODO(team-lead): expose POST /files/{id}/comments in the public v3
	// client API so this example can create the comment through c-vtapi.
	puts("add comment is not exposed by the current c-vtapi v3 API");
	puts("see https://docs.virustotal.com/reference/files-comments-post");
	return 0;
}

int main(int argc, char** argv) {
	const char* api_key;
	vt_client* client;
	vt_iter* comments = NULL;
	vt_status status;
	int exit_code = 0;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: %s <file-id> [comment]\n", argv[0]);
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

	if (argc == 3) {
		exit_code = add_comment(client, argv[1], argv[2]);
		goto cleanup;
	}

	status = vt_files_relationships(client, argv[1], "comments",
	                                comment_limit, &comments);
	if (status != VT_OK) {
		exit_code = report_status(client, "list comments", status);
		goto cleanup;
	}

	status = list_comments(comments);
	if (status != VT_OK) {
		exit_code = report_status(client, "read comment page", status);
	}

cleanup:
	vt_iter_free(comments);
	vt_client_free(client);
	return exit_code;
}
