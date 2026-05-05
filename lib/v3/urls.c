/* SPDX-License-Identifier: Apache-2.0 */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vt/urls.h>

#include "http.h"

static bool is_empty(const char* value) {
	return value == NULL || value[0] == '\0';
}

static bool is_unreserved(unsigned char value) {
	return isalnum(value) || value == '-' || value == '.' || value == '_' ||
	       value == '~';
}

static char* percent_escape(const char* value, bool space_as_plus) {
	static const char hex[] = "0123456789ABCDEF";
	size_t escaped_len = 0;

	if (value == NULL) {
		return NULL;
	}

	for (const unsigned char* current = (const unsigned char*)value;
	     *current != '\0'; current++) {
		if (is_unreserved(*current) ||
		    (space_as_plus && *current == ' ')) {
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
		if (space_as_plus && *current == ' ') {
			*out++ = '+';
		} else if (is_unreserved(*current)) {
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
	char* escaped_id = percent_escape(id, false);
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
	char* escaped_child = percent_escape(child, false);
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

static vt_status send_request(vt_client* client, const char* method,
                              const char* path, const void* body,
                              size_t body_len) {
	vt_http_request request = {
	    .method = method,
	    .path = path,
	    .body = body,
	    .body_len = body_len,
	};
	vt_http_response response = {0};

	const vt_status status =
	    vt_http_send_default(client, &request, &response);
	free(response.body);
	if (status != VT_OK) {
		return status;
	}

	/* TODO(architect-review): Materialize vt_object/vt_iter from response.
	 */
	return VT_UNIMPL;
}

static vt_status send_path(vt_client* client, const char* method, char* path,
                           const void* body, size_t body_len) {
	if (path == NULL) {
		return VT_NOMEM;
	}

	const vt_status status =
	    send_request(client, method, path, body, body_len);
	free(path);
	return status;
}

static char* form_body(const char* name, const char* value) {
	char* encoded = percent_escape(value, true);
	if (encoded == NULL) {
		return NULL;
	}

	const size_t name_len = strlen(name);
	const size_t encoded_len = strlen(encoded);
	if (name_len > SIZE_MAX - encoded_len - 2) {
		free(encoded);
		return NULL;
	}

	char* body = malloc(name_len + encoded_len + 2);
	if (body == NULL) {
		free(encoded);
		return NULL;
	}

	memcpy(body, name, name_len);
	body[name_len] = '=';
	memcpy(body + name_len + 1, encoded, encoded_len + 1);
	free(encoded);
	return body;
}

static char* json_escape_string(const char* text) {
	static const char hex[] = "0123456789ABCDEF";
	size_t escaped_len = 0;

	for (const unsigned char* current = (const unsigned char*)text;
	     *current != '\0'; current++) {
		switch (*current) {
			case '"':
			case '\\':
			case '\b':
			case '\f':
			case '\n':
			case '\r':
			case '\t':
				if (escaped_len > SIZE_MAX - 2) {
					return NULL;
				}
				escaped_len += 2;
				break;
			default:
				if (*current < 0x20) {
					if (escaped_len > SIZE_MAX - 6) {
						return NULL;
					}
					escaped_len += 6;
				} else {
					escaped_len++;
				}
				break;
		}
	}

	char* escaped = malloc(escaped_len + 1);
	if (escaped == NULL) {
		return NULL;
	}

	char* out = escaped;
	for (const unsigned char* current = (const unsigned char*)text;
	     *current != '\0'; current++) {
		switch (*current) {
			case '"':
				*out++ = '\\';
				*out++ = '"';
				break;
			case '\\':
				*out++ = '\\';
				*out++ = '\\';
				break;
			case '\b':
				*out++ = '\\';
				*out++ = 'b';
				break;
			case '\f':
				*out++ = '\\';
				*out++ = 'f';
				break;
			case '\n':
				*out++ = '\\';
				*out++ = 'n';
				break;
			case '\r':
				*out++ = '\\';
				*out++ = 'r';
				break;
			case '\t':
				*out++ = '\\';
				*out++ = 't';
				break;
			default:
				if (*current < 0x20) {
					*out++ = '\\';
					*out++ = 'u';
					*out++ = '0';
					*out++ = '0';
					*out++ = hex[*current >> 4];
					*out++ = hex[*current & 0x0f];
				} else {
					*out++ = (char)*current;
				}
				break;
		}
	}
	*out = '\0';

	return escaped;
}

static char* comment_body(const char* text) {
	static const char prefix[] =
	    "{\"data\":{\"type\":\"comment\",\"attributes\":{\"text\":\"";
	static const char suffix[] = "\"}}}";
	char* escaped = json_escape_string(text);
	if (escaped == NULL) {
		return NULL;
	}

	const size_t prefix_len = strlen(prefix);
	const size_t escaped_len = strlen(escaped);
	const size_t suffix_len = strlen(suffix);
	if (prefix_len > SIZE_MAX - escaped_len - suffix_len - 1) {
		free(escaped);
		return NULL;
	}

	char* body = malloc(prefix_len + escaped_len + suffix_len + 1);
	if (body == NULL) {
		free(escaped);
		return NULL;
	}

	memcpy(body, prefix, prefix_len);
	memcpy(body + prefix_len, escaped, escaped_len);
	memcpy(body + prefix_len + escaped_len, suffix, suffix_len + 1);
	free(escaped);
	return body;
}

vt_status vt_urls_get(vt_client* client, const char* url_id,
                      vt_object** out_url) {
	if (out_url != NULL) {
		*out_url = NULL;
	}
	if (client == NULL || is_empty(url_id) || out_url == NULL) {
		return VT_INVALID_ARG;
	}

	return send_path(client, "GET", object_path("urls", url_id), NULL, 0);
}

vt_status vt_urls_submit(vt_client* client, const char* url,
                         vt_object** out_analysis) {
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	if (client == NULL || is_empty(url) || out_analysis == NULL) {
		return VT_INVALID_ARG;
	}

	char* body = form_body("url", url);
	if (body == NULL) {
		return VT_NOMEM;
	}

	const vt_status status = send_path(
	    client, "POST", checked_join("/", "urls"), body, strlen(body));
	free(body);
	return status;
}

vt_status vt_urls_analyse(vt_client* client, const char* url_id,
                          vt_object** out_analysis) {
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	if (client == NULL || is_empty(url_id) || out_analysis == NULL) {
		return VT_INVALID_ARG;
	}

	return send_path(client, "POST", nested_path("urls", url_id, "analyse"),
	                 NULL, 0);
}

vt_status vt_urls_relationships(vt_client* client, const char* url_id,
                                const char* relationship, uint32_t limit,
                                vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (client == NULL || is_empty(url_id) || is_empty(relationship) ||
	    out_iter == NULL) {
		return VT_INVALID_ARG;
	}

	return send_path(
	    client, "GET",
	    with_limit(nested_path("urls", url_id, relationship), limit), NULL,
	    0);
}

vt_status vt_urls_comments(vt_client* client, const char* url_id,
                           uint32_t limit, vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (client == NULL || is_empty(url_id) || out_iter == NULL) {
		return VT_INVALID_ARG;
	}

	return send_path(
	    client, "GET",
	    with_limit(nested_path("urls", url_id, "comments"), limit), NULL,
	    0);
}

vt_status vt_urls_add_comment(vt_client* client, const char* url_id,
                              const char* text, vt_object** out_comment) {
	if (out_comment != NULL) {
		*out_comment = NULL;
	}
	if (client == NULL || is_empty(url_id) || text == NULL ||
	    out_comment == NULL) {
		return VT_INVALID_ARG;
	}

	char* body = comment_body(text);
	if (body == NULL) {
		return VT_NOMEM;
	}

	const vt_status status =
	    send_path(client, "POST", nested_path("urls", url_id, "comments"),
	              body, strlen(body));
	free(body);
	return status;
}
