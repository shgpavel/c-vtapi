/* SPDX-License-Identifier: Apache-2.0 */

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vt/files.h>

#include "http.h"

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

static vt_status send_request(vt_client* client, vt_http_method method,
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

static vt_status send_path(vt_client* client, vt_http_method method, char* path,
                           const void* body, size_t body_len) {
	if (path == NULL) {
		return VT_NOMEM;
	}

	const vt_status status =
	    send_request(client, method, path, body, body_len);
	free(path);
	return status;
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

static char* multipart_filename(const char* filename) {
	const char* fallback = "file";
	const char* source = is_empty(filename) ? fallback : filename;
	const size_t source_len = strlen(source);
	char* escaped = malloc(source_len + 1);
	if (escaped == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < source_len; i++) {
		const char value = source[i];
		escaped[i] = value == '"' || value == '\\' || value == '\r' ||
		                     value == '\n'
		                 ? '_'
		                 : value;
	}
	escaped[source_len] = '\0';
	return escaped;
}

static vt_status multipart_body(const char* filename, const void* data,
                                size_t data_len, char** out_body,
                                size_t* out_body_len) {
	static const char boundary[] = "----vtapi-v3-resource-boundary";
	static const char content_type[] =
	    "Content-Type: application/octet-stream";
	char* safe_filename = multipart_filename(filename);
	if (safe_filename == NULL) {
		return VT_NOMEM;
	}

	const int prefix_len =
	    snprintf(NULL, 0,
	             "--%s\r\nContent-Disposition: form-data; name=\"file\"; "
	             "filename=\"%s\"\r\n%s\r\n\r\n",
	             boundary, safe_filename, content_type);
	const int suffix_len = snprintf(NULL, 0, "\r\n--%s--\r\n", boundary);
	if (prefix_len < 0 || suffix_len < 0) {
		free(safe_filename);
		return VT_UNKNOWN;
	}

	const size_t prefix_size = (size_t)prefix_len;
	const size_t suffix_size = (size_t)suffix_len;
	if (prefix_size > SIZE_MAX - data_len ||
	    prefix_size + data_len > SIZE_MAX - suffix_size) {
		free(safe_filename);
		return VT_NOMEM;
	}

	const size_t body_len = prefix_size + data_len + suffix_size;
	if (body_len == SIZE_MAX) {
		free(safe_filename);
		return VT_NOMEM;
	}

	char* body = malloc(body_len + 1);
	if (body == NULL) {
		free(safe_filename);
		return VT_NOMEM;
	}

	snprintf(body, prefix_size + 1,
	         "--%s\r\nContent-Disposition: form-data; name=\"file\"; "
	         "filename=\"%s\"\r\n%s\r\n\r\n",
	         boundary, safe_filename, content_type);
	if (data_len > 0) {
		memcpy(body + prefix_size, data, data_len);
	}
	snprintf(body + prefix_size + data_len, suffix_size + 1,
	         "\r\n--%s--\r\n", boundary);

	free(safe_filename);
	*out_body = body;
	*out_body_len = body_len;
	return VT_OK;
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

static vt_status read_file(const char* path, unsigned char** out_data,
                           size_t* out_data_len) {
	FILE* file = fopen(path, "rb");
	if (file == NULL) {
		return VT_IO;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return VT_IO;
	}

	const long length = ftell(file);
	if (length < 0) {
		fclose(file);
		return VT_IO;
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return VT_IO;
	}

	unsigned char* data = malloc(length == 0 ? 1 : (size_t)length);
	if (data == NULL) {
		fclose(file);
		return VT_NOMEM;
	}

	const size_t data_len = (size_t)length;
	const size_t read_len = fread(data, 1, data_len, file);
	if (read_len != data_len || ferror(file)) {
		free(data);
		fclose(file);
		return VT_IO;
	}

	if (fclose(file) != 0) {
		free(data);
		return VT_IO;
	}

	*out_data = data;
	*out_data_len = data_len;
	return VT_OK;
}

vt_status vt_files_get(vt_client* client, const char* file_id,
                       vt_object** out_file) {
	if (out_file != NULL) {
		*out_file = NULL;
	}
	if (client == NULL || is_empty(file_id) || out_file == NULL) {
		return VT_INVALID_ARG;
	}

	return send_path(client, VT_HTTP_GET, object_path("files", file_id), NULL, 0);
}

vt_status vt_files_submit_path(vt_client* client, const char* path,
                               vt_object** out_analysis) {
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	if (client == NULL || is_empty(path) || out_analysis == NULL) {
		return VT_INVALID_ARG;
	}

	unsigned char* data = NULL;
	size_t data_len = 0;
	const vt_status read_status = read_file(path, &data, &data_len);
	if (read_status != VT_OK) {
		return read_status;
	}

	const vt_status submit_status = vt_files_submit_buffer(
	    client, path_basename(path), data, data_len, out_analysis);
	free(data);
	return submit_status;
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

	char* body = NULL;
	size_t body_len = 0;
	const vt_status body_status =
	    multipart_body(filename, data, data_len, &body, &body_len);
	if (body_status != VT_OK) {
		return body_status;
	}

	const vt_status send_status = send_path(
	    client, VT_HTTP_POST, checked_join("/", "files"), body, body_len);
	free(body);
	return send_status;
}

vt_status vt_files_upload_url(vt_client* client, vt_object** out_upload_url) {
	if (out_upload_url != NULL) {
		*out_upload_url = NULL;
	}
	if (client == NULL || out_upload_url == NULL) {
		return VT_INVALID_ARG;
	}

	return send_path(client, VT_HTTP_GET, checked_join("/files/", "upload_url"),
	                 NULL, 0);
}

vt_status vt_files_analyse(vt_client* client, const char* file_id,
                           vt_object** out_analysis) {
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	if (client == NULL || is_empty(file_id) || out_analysis == NULL) {
		return VT_INVALID_ARG;
	}

	return send_path(client, VT_HTTP_POST,
	                 nested_path("files", file_id, "analyse"), NULL, 0);
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

	return send_path(
	    client, VT_HTTP_GET,
	    with_limit(nested_path("files", file_id, relationship), limit),
	    NULL, 0);
}

vt_status vt_files_comments(vt_client* client, const char* file_id,
                            uint32_t limit, vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (client == NULL || is_empty(file_id) || out_iter == NULL) {
		return VT_INVALID_ARG;
	}

	return send_path(
	    client, VT_HTTP_GET,
	    with_limit(nested_path("files", file_id, "comments"), limit), NULL,
	    0);
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

	char* body = comment_body(text);
	if (body == NULL) {
		return VT_NOMEM;
	}

	const vt_status status =
	    send_path(client, VT_HTTP_POST, nested_path("files", file_id, "comments"),
	              body, strlen(body));
	free(body);
	return status;
}
