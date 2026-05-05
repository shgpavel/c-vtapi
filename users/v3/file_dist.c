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

static int write_feed(const char* path, const void* data, size_t data_len) {
	FILE* output = stdout;
	int exit_code = 0;

	if (path != NULL) {
		output = fopen(path, "wb");
		if (output == NULL) {
			perror(path);
			return 1;
		}
	}

	if (data_len > 0 && fwrite(data, 1, data_len, output) != data_len) {
		perror(path != NULL ? path : "stdout");
		exit_code = 1;
	}
	if (fflush(output) != 0) {
		perror(path != NULL ? path : "stdout");
		exit_code = 1;
	}
	if (path != NULL && fclose(output) != 0) {
		perror(path);
		exit_code = 1;
	}

	return exit_code;
}

int main(int argc, char** argv) {
	const char* api_key;
	vt_client* client;
	void* feed = NULL;
	size_t feed_len = 0;
	vt_status status;
	int exit_code = 0;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: %s <time YYYYMMDDHHmm> [output.bz2]\n",
		        argv[0]);
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

	status = vt_feeds_files(client, argv[1], &feed, &feed_len);
	if (status != VT_OK) {
		exit_code = report_status(client, "fetch file feed", status);
		goto cleanup;
	}

	exit_code = write_feed(argc == 3 ? argv[2] : NULL, feed, feed_len);
	if (exit_code == 0) {
		fprintf(stderr, "wrote %zu bz2-compressed bytes\n", feed_len);
	}

cleanup:
	free(feed);
	vt_client_free(client);
	return exit_code;
}
