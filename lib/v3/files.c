/* SPDX-License-Identifier: Apache-2.0 */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vt/files.h>

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

static const char* path_basename(const char* path) {
	const char* slash = strrchr(path, '/');
	const char* backslash = strrchr(path, '\\');
	const char* basename = NULL;

	if (slash == NULL) {
		basename = backslash;
	} else if (backslash == NULL) {
		basename = slash;
	} else {
		basename = slash > backslash ? slash : backslash;
	}

	if (basename == NULL || basename[1] == '\0') {
		return "file";
	}
	return basename + 1;
}

vt_status vt_files_get(vt_client* client, const char* file_id,
                       vt_object** out_file) {
	if (out_file != NULL) {
		*out_file = NULL;
	}
	if (client == NULL || is_empty(file_id) || out_file == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_send_path_object(client, VT_HTTP_GET,
	                                object_path("files", file_id), NULL, 0,
	                                NULL, out_file);
}

vt_status vt_files_submit_path(vt_client* client, const char* path,
                               vt_object** out_analysis) {
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	if (client == NULL || is_empty(path) || out_analysis == NULL) {
		return VT_INVALID_ARG;
	}

	const vt_http_multipart_part part = {
	    .name = "file",
	    .filename = path_basename(path),
	    .content_type = "application/octet-stream",
	    .source = VT_HTTP_MULTIPART_FILE,
	    .path = path,
	};
	return vt_page_send_path_multipart(client, VT_HTTP_POST,
	                                   checked_join("/", "files"), &part, 1,
	                                   out_analysis);
}

vt_status vt_files_submit_buffer(vt_client* client, const char* filename,
                                 const void* data, size_t data_len,
                                 vt_object** out_analysis) {
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	if (client == NULL || is_empty(filename) ||
	    (data == NULL && data_len > 0) || out_analysis == NULL) {
		return VT_INVALID_ARG;
	}

	const vt_http_multipart_part part = {
	    .name = "file",
	    .filename = filename,
	    .content_type = "application/octet-stream",
	    .source = VT_HTTP_MULTIPART_DATA,
	    .data = data,
	    .data_len = data_len,
	};
	return vt_page_send_path_multipart(client, VT_HTTP_POST,
	                                   checked_join("/", "files"), &part, 1,
	                                   out_analysis);
}

vt_status vt_files_upload_url(vt_client* client, vt_object** out_upload_url) {
	if (out_upload_url != NULL) {
		*out_upload_url = NULL;
	}
	if (client == NULL || out_upload_url == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_send_path_object(client, VT_HTTP_GET,
	                                checked_join("/files/", "upload_url"),
	                                NULL, 0, NULL, out_upload_url);
}

vt_status vt_files_analyse(vt_client* client, const char* file_id,
                           vt_object** out_analysis) {
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	if (client == NULL || is_empty(file_id) || out_analysis == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_send_path_object(
	    client, VT_HTTP_POST, nested_path("files", file_id, "analyse"),
	    NULL, 0, NULL, out_analysis);
}

vt_status vt_files_relationships(vt_client* client, const char* file_id,
                                 const char* relationship, uint32_t limit,
                                 vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (client == NULL || is_empty(file_id) || is_empty(relationship) ||
	    out_iter == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_iter_from_path(
	    client,
	    with_limit(nested_path("files", file_id, relationship), limit),
	    out_iter);
}

vt_status vt_files_comments(vt_client* client, const char* file_id,
                            uint32_t limit, vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (client == NULL || is_empty(file_id) || out_iter == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_iter_from_path(
	    client,
	    with_limit(nested_path("files", file_id, "comments"), limit),
	    out_iter);
}

vt_status vt_files_add_comment(vt_client* client, const char* file_id,
                               const char* text, vt_object** out_comment) {
	if (out_comment != NULL) {
		*out_comment = NULL;
	}
	if (client == NULL || is_empty(file_id) || text == NULL ||
	    out_comment == NULL) {
		return VT_INVALID_ARG;
	}

	return vt_page_send_path_comment(
	    client, nested_path("files", file_id, "comments"), text,
	    out_comment);
}
