/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson.h>

#include "http.h"

struct vt_iter {
	vt_client* client;
	vt_iter_parse_page_fn parse_page;
	void* userdata;
	vt_object** objects;
	size_t object_count;
	size_t object_index;
	char* next_url;
	char* cursor;
	vt_status last_error;
};

static char* vt_iter_strdup(const char* value) {
	if (value == NULL) {
		return NULL;
	}

	const size_t len = strlen(value);
	char* copy = malloc(len + 1);
	if (copy == NULL) {
		return NULL;
	}

	memcpy(copy, value, len + 1);
	return copy;
}

static char* vt_iter_strdup_json_string(yyjson_val* value) {
	if (!yyjson_is_str(value)) {
		return NULL;
	}

	const char* string = yyjson_get_str(value);
	const size_t len = yyjson_get_len(value);
	char* copy = malloc(len + 1);
	if (copy == NULL) {
		return NULL;
	}

	memcpy(copy, string, len);
	copy[len] = '\0';
	return copy;
}

static yyjson_val* vt_iter_page_member(yyjson_val* root, const char* object_key,
                                       const char* member_key) {
	yyjson_val* object =
	    yyjson_is_obj(root) ? yyjson_obj_get(root, object_key) : NULL;
	return yyjson_is_obj(object) ? yyjson_obj_get(object, member_key) : NULL;
}

static void vt_iter_extract_page_links(const vt_http_response* response,
                                       char** out_next_url,
                                       char** out_cursor) {
	if (response == NULL || response->body == NULL || response->body_len == 0) {
		return;
	}

	yyjson_doc* doc = yyjson_read_opts((char*)response->body,
	                                   response->body_len,
	                                   YYJSON_READ_NOFLAG, NULL, NULL);
	if (doc == NULL) {
		return;
	}

	yyjson_val* root = yyjson_doc_get_root(doc);
	if (*out_next_url == NULL) {
		*out_next_url = vt_iter_strdup_json_string(
		    vt_iter_page_member(root, "links", "next"));
	}
	if (*out_cursor == NULL) {
		*out_cursor = vt_iter_strdup_json_string(
		    vt_iter_page_member(root, "meta", "cursor"));
	}

	yyjson_doc_free(doc);
}

static char* vt_iter_extract_cursor_from_url(const char* url) {
	if (url == NULL) {
		return NULL;
	}

	const char* cursor = strstr(url, "?cursor=");
	if (cursor == NULL) {
		cursor = strstr(url, "&cursor=");
	}
	if (cursor == NULL) {
		return NULL;
	}

	cursor += strlen("?cursor=");
	const char* end = strchr(cursor, '&');
	const size_t len =
	    end == NULL ? strlen(cursor) : (size_t)(end - cursor);
	char* copy = malloc(len + 1);
	if (copy == NULL) {
		return NULL;
	}

	memcpy(copy, cursor, len);
	copy[len] = '\0';
	return copy;
}

static bool vt_iter_is_unreserved(unsigned char c) {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '-' || c == '.' ||
	       c == '_' || c == '~';
}

static char* vt_iter_percent_encode(const char* value) {
	static const char hex[] = "0123456789ABCDEF";

	if (value == NULL) {
		return NULL;
	}

	size_t encoded_len = 0;
	for (const unsigned char* ptr = (const unsigned char*)value; *ptr != 0;
	     ptr++) {
		if (vt_iter_is_unreserved(*ptr)) {
			if (encoded_len > SIZE_MAX - 2) {
				return NULL;
			}
			encoded_len++;
		} else {
			if (encoded_len > SIZE_MAX - 4) {
				return NULL;
			}
			encoded_len += 3;
		}
	}

	char* encoded = malloc(encoded_len + 1);
	if (encoded == NULL) {
		return NULL;
	}

	char* out = encoded;
	for (const unsigned char* ptr = (const unsigned char*)value; *ptr != 0;
	     ptr++) {
		if (vt_iter_is_unreserved(*ptr)) {
			*out++ = (char)*ptr;
		} else {
			*out++ = '%';
			*out++ = hex[*ptr >> 4];
			*out++ = hex[*ptr & 0x0fU];
		}
	}
	*out = '\0';
	return encoded;
}

static char* vt_iter_url_with_cursor(const char* url, const char* cursor) {
	char* copy = vt_iter_strdup(url);
	if (copy == NULL) {
		return NULL;
	}

	char* escaped = vt_iter_percent_encode(cursor);
	if (escaped == NULL) {
		free(copy);
		return NULL;
	}

	const char* separator =
	    strchr(copy, '?') == NULL ? "?cursor=" : "&cursor=";
	const size_t lhs_len = strlen(copy);
	const size_t sep_len = strlen(separator);
	const size_t cursor_len = strlen(escaped);
	if (SIZE_MAX - lhs_len <= sep_len ||
	    SIZE_MAX - lhs_len - sep_len <= cursor_len) {
		free(escaped);
		free(copy);
		return NULL;
	}

	char* next = realloc(copy, lhs_len + sep_len + cursor_len + 1);
	if (next == NULL) {
		free(escaped);
		free(copy);
		return NULL;
	}

	memcpy(next + lhs_len, separator, sep_len);
	memcpy(next + lhs_len + sep_len, escaped, cursor_len + 1);
	free(escaped);
	return next;
}

static void vt_iter_clear_objects(vt_iter* iter) {
	if (iter == NULL || iter->objects == NULL) {
		return;
	}

	for (size_t i = iter->object_index; i < iter->object_count; i++) {
		vt_object_free(iter->objects[i]);
	}
	free(iter->objects);
	iter->objects = NULL;
	iter->object_count = 0;
	iter->object_index = 0;
}

static void vt_iter_free_object_array(vt_object** objects,
                                      size_t object_count) {
	if (objects == NULL) {
		return;
	}

	for (size_t i = 0; i < object_count; i++) {
		vt_object_free(objects[i]);
	}
	free(objects);
}

static vt_status vt_iter_set_page(vt_iter* iter, vt_object** objects,
                                  size_t object_count, char* next_url,
                                  char* cursor, const char* request_url) {
	if (cursor == NULL && next_url != NULL) {
		cursor = vt_iter_extract_cursor_from_url(next_url);
	}
	if (next_url == NULL && cursor != NULL) {
		next_url = vt_iter_url_with_cursor(request_url, cursor);
		if (next_url == NULL) {
			free(cursor);
			return VT_NOMEM;
		}
	}

	vt_iter_clear_objects(iter);
	iter->objects = objects;
	iter->object_count = object_count;
	iter->object_index = 0;

	free(iter->next_url);
	free(iter->cursor);
	iter->next_url = next_url;
	iter->cursor = cursor;
	return VT_OK;
}

vt_status vt_iter_new(vt_client* client, const char* initial_url,
                      vt_iter_parse_page_fn parse_page, void* userdata,
                      vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (client == NULL || initial_url == NULL || initial_url[0] == '\0' ||
	    out_iter == NULL) {
		return vt_client_set_error(client, VT_INVALID_ARG,
		                           "iterator URL is required");
	}

	vt_iter* iter = calloc(1, sizeof(*iter));
	if (iter == NULL) {
		return vt_client_set_error(client, VT_NOMEM,
		                           "failed to allocate iterator");
	}

	iter->client = client;
	iter->parse_page = parse_page;
	iter->userdata = userdata;
	iter->next_url = vt_iter_strdup(initial_url);
	iter->cursor = vt_iter_extract_cursor_from_url(initial_url);
	iter->last_error = VT_OK;
	if (iter->next_url == NULL) {
		vt_iter_free(iter);
		return vt_client_set_error(client, VT_NOMEM,
		                           "failed to store iterator URL");
	}

	*out_iter = iter;
	return VT_OK;
}

vt_status vt_iter_next(vt_iter* iter, vt_object** out_object) {
	if (out_object != NULL) {
		*out_object = NULL;
	}
	if (iter == NULL || out_object == NULL) {
		return VT_INVALID_ARG;
	}

	if (iter->object_index < iter->object_count) {
		*out_object = iter->objects[iter->object_index];
		iter->objects[iter->object_index] = NULL;
		iter->object_index++;
		iter->last_error = VT_OK;
		return VT_OK;
	}
	vt_iter_clear_objects(iter);

	if (iter->next_url == NULL) {
		iter->last_error = VT_OK;
		return VT_OK;
	}

	char* request_url = vt_iter_strdup(iter->next_url);
	if (request_url == NULL) {
		iter->last_error = VT_NOMEM;
		return VT_NOMEM;
	}

	vt_http_request request = {
	    .method = VT_HTTP_GET,
	    .path = request_url,
	};
	vt_http_response response = {0};
	vt_status status = vt_client_send(iter->client, &request, &response);
	if (status != VT_OK) {
		free(request_url);
		vt_http_response_cleanup(&response);
		iter->last_error = status;
		return status;
	}

	vt_object** objects = NULL;
	size_t object_count = 0;
	char* next_url = NULL;
	char* cursor = NULL;
	if (iter->parse_page != NULL) {
		status = iter->parse_page(&response, &objects, &object_count,
		                          &next_url, &cursor, iter->userdata);
		if (status != VT_OK) {
			free(request_url);
			free(next_url);
			free(cursor);
			vt_iter_free_object_array(objects, object_count);
			vt_http_response_cleanup(&response);
			iter->last_error = status;
			return status;
		}
	}
	if (objects == NULL && object_count != 0) {
		free(request_url);
		free(next_url);
		free(cursor);
		vt_http_response_cleanup(&response);
		iter->last_error = VT_INVALID_ARG;
		return VT_INVALID_ARG;
	}

	vt_iter_extract_page_links(&response, &next_url, &cursor);

	status = vt_iter_set_page(iter, objects, object_count, next_url, cursor,
	                          request_url);
	free(request_url);
	vt_http_response_cleanup(&response);
	if (status != VT_OK) {
		vt_iter_free_object_array(objects, object_count);
		free(next_url);
		iter->last_error = status;
		return status;
	}

	if (iter->object_index < iter->object_count) {
		*out_object = iter->objects[iter->object_index];
		iter->objects[iter->object_index] = NULL;
		iter->object_index++;
	}

	iter->last_error = VT_OK;
	return VT_OK;
}

void vt_iter_free(vt_iter* iter) {
	if (iter == NULL) {
		return;
	}

	vt_iter_clear_objects(iter);
	free(iter->next_url);
	free(iter->cursor);
	free(iter);
}

vt_status vt_iter_error(const vt_iter* iter) {
	return iter == NULL ? VT_INVALID_ARG : iter->last_error;
}

const char* vt_iter_cursor(const vt_iter* iter) {
	return iter == NULL ? NULL : iter->cursor;
}
