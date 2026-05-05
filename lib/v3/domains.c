/* SPDX-License-Identifier: Apache-2.0 */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vt/domains.h>

#include "http.h"
#include "page.h"

static bool is_empty(const char* value) {
	return value == NULL || value[0] == '\0';
}

static bool is_path_unreserved(unsigned char value) {
	return isalnum(value) || value == '-' || value == '.' || value == '_' ||
	       value == '~';
}

static char* path_escape(const char* value) {
	static const char hex[] = "0123456789ABCDEF";
	size_t escaped_len = 0;

	if (value == NULL) {
		return NULL;
	}

	for (const unsigned char* current = (const unsigned char*)value;
	     *current != '\0'; current++) {
		if (is_path_unreserved(*current)) {
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
		if (is_path_unreserved(*current)) {
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

static char* checked_join(const char* first, const char* second) {
	const size_t first_len = strlen(first);
	const size_t second_len = strlen(second);

	if (first_len > SIZE_MAX - second_len - 1) {
		return NULL;
	}

	char* joined = malloc(first_len + second_len + 1);
	if (joined == NULL) {
		return NULL;
	}

	memcpy(joined, first, first_len);
	memcpy(joined + first_len, second, second_len + 1);
	return joined;
}

static char* object_path(const char* collection, const char* id) {
	char* escaped_id = path_escape(id);
	if (escaped_id == NULL) {
		return NULL;
	}

	char* prefix = checked_join("/", collection);
	if (prefix == NULL) {
		free(escaped_id);
		return NULL;
	}

	char* prefix_slash = checked_join(prefix, "/");
	free(prefix);
	if (prefix_slash == NULL) {
		free(escaped_id);
		return NULL;
	}

	char* path = checked_join(prefix_slash, escaped_id);
	free(prefix_slash);
	free(escaped_id);
	return path;
}

static char* nested_path(const char* collection, const char* id,
                         const char* child) {
	char* base = object_path(collection, id);
	char* escaped_child = path_escape(child);
	if (base == NULL || escaped_child == NULL) {
		free(base);
		free(escaped_child);
		return NULL;
	}

	char* base_slash = checked_join(base, "/");
	free(base);
	if (base_slash == NULL) {
		free(escaped_child);
		return NULL;
	}

	char* path = checked_join(base_slash, escaped_child);
	free(base_slash);
	free(escaped_child);
	return path;
}

static char* with_limit(char* path, uint32_t limit) {
	if (path == NULL || limit == 0) {
		return path;
	}

	const int needed = snprintf(NULL, 0, "%s?limit=%" PRIu32, path, limit);
	if (needed < 0) {
		free(path);
		return NULL;
	}

	char* limited = malloc((size_t)needed + 1);
	if (limited == NULL) {
		free(path);
		return NULL;
	}

	snprintf(limited, (size_t)needed + 1, "%s?limit=%" PRIu32, path, limit);
	free(path);
	return limited;
}

vt_status vt_domains_get(vt_client* client, const char* domain,
                         vt_object** out_domain) {
	if (out_domain != NULL) {
		*out_domain = NULL;
	}
	if (client == NULL || is_empty(domain) || out_domain == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_send_path_object(client, VT_HTTP_GET,
	                                object_path("domains", domain), NULL, 0,
	                                NULL, out_domain);
}

vt_status vt_domains_relationships(vt_client* client, const char* domain,
                                   const char* relationship, uint32_t limit,
                                   vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (client == NULL || is_empty(domain) || is_empty(relationship) ||
	    out_iter == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_iter_from_path(
	    client,
	    with_limit(nested_path("domains", domain, relationship), limit),
	    out_iter);
}

vt_status vt_domains_comments(vt_client* client, const char* domain,
                              uint32_t limit, vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (client == NULL || is_empty(domain) || out_iter == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_iter_from_path(
	    client,
	    with_limit(nested_path("domains", domain, "comments"), limit),
	    out_iter);
}

vt_status vt_domains_add_comment(vt_client* client, const char* domain,
                                 const char* text, vt_object** out_comment) {
	if (out_comment != NULL) {
		*out_comment = NULL;
	}
	if (client == NULL || is_empty(domain) || text == NULL ||
	    out_comment == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_send_path_comment(
	    client, nested_path("domains", domain, "comments"), text,
	    out_comment);
}
