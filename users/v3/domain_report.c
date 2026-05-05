/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <vt/vt.h>

enum { subdomain_limit = 10 };

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

static vt_status print_subdomains(vt_iter* iter) {
	for (unsigned int count = 0; count < subdomain_limit; ++count) {
		vt_object* subdomain = NULL;
		vt_status status = vt_iter_next(iter, &subdomain);

		if (status != VT_OK) {
			return status;
		}
		if (subdomain == NULL) {
			break;
		}

		printf("subdomain: %s\n", vt_object_id(subdomain) != NULL
		                              ? vt_object_id(subdomain)
		                              : "unavailable");
		vt_object_free(subdomain);
	}

	return VT_OK;
}

int main(int argc, char** argv) {
	const char* api_key;
	vt_client* client;
	vt_object* domain = NULL;
	vt_iter* subdomains = NULL;
	vt_status status;
	int exit_code = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <domain>\n", argv[0]);
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

	status = vt_domains_get(client, argv[1], &domain);
	if (status != VT_OK) {
		exit_code = report_status(client, "get domain", status);
		goto cleanup;
	}

	printf("id: %s\n", vt_object_id(domain) != NULL ? vt_object_id(domain)
	                                                : "unavailable");
	printf("last_analysis_stats: %s\n",
	       vt_object_attribute(domain, "last_analysis_stats") != NULL
	           ? vt_object_attribute(domain, "last_analysis_stats")
	           : "unavailable");

	status = vt_domains_relationships(client, argv[1], "subdomains",
	                                  subdomain_limit, &subdomains);
	if (status != VT_OK) {
		exit_code = report_status(client, "list subdomains", status);
		goto cleanup;
	}

	status = print_subdomains(subdomains);
	if (status != VT_OK) {
		exit_code =
		    report_status(client, "read subdomain page", status);
	}

cleanup:
	vt_iter_free(subdomains);
	vt_object_free(domain);
	vt_client_free(client);
	return exit_code;
}
