/* SPDX-License-Identifier: Apache-2.0 */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vt/intelligence.h>

#include "page.h"

static bool is_empty(const char* value) {
	return value == NULL || value[0] == '\0';
}

static bool is_query_unreserved(unsigned char value) {
	return isalnum(value) || value == '-' || value == '.' || value == '_' ||
	       value == '~';
}

static char* query_escape(const char* value) {
	static const char hex[] = "0123456789ABCDEF";
	size_t escaped_len = 0;

	if (value == NULL) {
		return NULL;
	}

	for (const unsigned char* current = (const unsigned char*)value;
	     *current != '\0'; current++) {
		if (is_query_unreserved(*current)) {
			escaped_len++;
		} else {
			if (escaped_len > SIZE_MAX - 3) {
				return NULL;
			}
			escaped_len += 3;
		}
	}

	char* escaped = malloc(escaped_len + 1);
	if (escaped == NULL) {
		return NULL;
	}

	char* out = escaped;
	for (const unsigned char* current = (const unsigned char*)value;
	     *current != '\0'; current++) {
		if (is_query_unreserved(*current)) {
			*out++ = (char)*current;
		} else {
			*out++ = '%';
			*out++ = hex[*current >> 4];
			*out++ = hex[*current & 0x0f];
		}
	}
	*out = '\0';

	return escaped;
}

static char* search_path(const char* query, uint32_t limit,
                         bool descriptors_only) {
	char* escaped_query = query_escape(query);
	if (escaped_query == NULL) {
		return NULL;
	}

	const char* descriptor_value = descriptors_only ? "true" : "false";
	const int needed =
	    snprintf(NULL, 0,
	             "/intelligence/search?query=%s&limit=%" PRIu32
	             "&descriptors_only=%s",
	             escaped_query, limit, descriptor_value);
	if (needed < 0) {
		free(escaped_query);
		return NULL;
	}

	char* path = malloc((size_t)needed + 1);
	if (path == NULL) {
		free(escaped_query);
		return NULL;
	}

	snprintf(path, (size_t)needed + 1,
	         "/intelligence/search?query=%s&limit=%" PRIu32
	         "&descriptors_only=%s",
	         escaped_query, limit, descriptor_value);
	free(escaped_query);
	return path;
}

vt_status vt_intelligence_search(vt_client* client, const char* query,
                                 uint32_t limit, bool descriptors_only,
                                 vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (client == NULL || is_empty(query) || out_iter == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_iter_from_path(
	    client, search_path(query, limit, descriptors_only), out_iter);
}
