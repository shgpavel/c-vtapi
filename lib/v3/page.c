/* SPDX-License-Identifier: Apache-2.0 */

#define VT_PAGE_NO_INLINE_ITER 1
#include "page.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

static char* vt_page_strdup(const char* value) {
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

static vt_status vt_page_set_error(vt_client* client, vt_status status,
                                   const char* message) {
	return vt_client_set_error(
	    client, status, message == NULL ? vt_status_str(status) : message);
}

static vt_status vt_page_json_status_error(vt_client* client,
                                           vt_status status) {
	if (status == VT_JSON) {
		return vt_page_set_error(client, status,
		                         "failed to parse JSON response");
	}
	if (status == VT_INVALID_ARG) {
		return vt_page_set_error(client, VT_JSON,
		                         "empty JSON response");
	}
	return vt_page_set_error(client, status, "API error response");
}

static vt_status vt_page_parse_json(vt_client* client,
                                    const vt_http_response* response,
                                    vt_json** out_json) {
	*out_json = NULL;
	if (response == NULL || response->body == NULL ||
	    response->body_len == 0) {
		return vt_page_json_status_error(client, VT_INVALID_ARG);
	}

	vt_status status = VT_OK;
	vt_json* json =
	    vt_json_parse(response->body, response->body_len, &status);
	if (status != VT_OK) {
		return vt_page_json_status_error(client, status);
	}

	const vt_status api_status = vt_json_error_status(json);
	if (api_status != VT_OK) {
		vt_json_free(json);
		return vt_page_json_status_error(client, api_status);
	}

	*out_json = json;
	return VT_OK;
}

static vt_status vt_page_response_object(vt_client* client,
                                         const vt_http_response* response,
                                         vt_object** out_object) {
	*out_object = NULL;

	vt_json* json = NULL;
	vt_status status = vt_page_parse_json(client, response, &json);
	if (status != VT_OK) {
		return status;
	}

	vt_object* object = vt_json_to_object(json);
	if (object == NULL) {
		vt_json_free(json);
		return vt_page_set_error(client, VT_JSON,
		                         "response data object is missing");
	}

	vt_json_free(json);
	*out_object = object;
	return VT_OK;
}

static void vt_page_free_object_array(vt_object** objects, size_t count) {
	if (objects == NULL) {
		return;
	}

	for (size_t i = 0; i < count; i++) {
		vt_object_free(objects[i]);
	}
	free(objects);
}

static void vt_page_free_json_page(vt_iter* page) {
	if (page == NULL) {
		return;
	}

	vt_json_doc_unref(page->doc);
	free(page);
}

static vt_status vt_page_copy_cursor_links(const vt_iter* page,
                                           char** out_next_url,
                                           char** out_cursor) {
	if (page->next_url != NULL) {
		*out_next_url = vt_page_strdup(page->next_url);
		if (*out_next_url == NULL) {
			return VT_NOMEM;
		}
	}

	if (page->cursor != NULL) {
		*out_cursor = vt_page_strdup(page->cursor);
		if (*out_cursor == NULL) {
			free(*out_next_url);
			*out_next_url = NULL;
			return VT_NOMEM;
		}
	}

	return VT_OK;
}

static vt_status vt_page_copy_objects(const vt_iter* page,
                                      vt_object*** out_objects,
                                      size_t* out_count) {
	*out_objects = NULL;
	*out_count = 0;

	if (page->count == 0) {
		return VT_OK;
	}

	vt_object** objects = calloc(page->count, sizeof(*objects));
	if (objects == NULL) {
		return VT_NOMEM;
	}

	size_t index = 0;
	size_t max = 0;
	yyjson_val* value = NULL;
	yyjson_arr_foreach(page->data, index, max, value) {
		objects[index] = vt_object_from_value(page->doc, value);
		if (objects[index] == NULL) {
			vt_page_free_object_array(objects, page->count);
			return VT_NOMEM;
		}
	}

	*out_objects = objects;
	*out_count = page->count;
	return VT_OK;
}

vt_status vt_page_parse_objects(const vt_http_response* response,
                                vt_object*** out_objects, size_t* out_count,
                                char** out_next_url, char** out_cursor,
                                void* userdata) {
	vt_client* client = userdata;
	if (out_objects != NULL) {
		*out_objects = NULL;
	}
	if (out_count != NULL) {
		*out_count = 0;
	}
	if (out_next_url != NULL) {
		*out_next_url = NULL;
	}
	if (out_cursor != NULL) {
		*out_cursor = NULL;
	}
	if (out_objects == NULL || out_count == NULL || out_next_url == NULL ||
	    out_cursor == NULL) {
		return vt_page_set_error(client, VT_INVALID_ARG,
		                         "page outputs are required");
	}

	vt_json* json = NULL;
	vt_status status = vt_page_parse_json(client, response, &json);
	if (status != VT_OK) {
		return status;
	}

	status = VT_OK;
	vt_iter* page = vt_json_to_page(json, NULL, &status);
	if (page == NULL) {
		vt_json_free(json);
		return vt_page_json_status_error(client, status);
	}

	vt_object** objects = NULL;
	size_t count = 0;
	status = vt_page_copy_objects(page, &objects, &count);
	if (status == VT_OK) {
		status =
		    vt_page_copy_cursor_links(page, out_next_url, out_cursor);
	}

	vt_page_free_json_page(page);
	vt_json_free(json);
	if (status != VT_OK) {
		vt_page_free_object_array(objects, count);
		free(*out_next_url);
		free(*out_cursor);
		*out_next_url = NULL;
		*out_cursor = NULL;
		return vt_page_set_error(client, status,
		                         "failed to materialize JSON page");
	}

	*out_objects = objects;
	*out_count = count;
	return VT_OK;
}

vt_status vt_page_send_object(vt_client* client, vt_http_method method,
                              const char* path, const void* body,
                              size_t body_len, const char* content_type,
                              const vt_http_multipart_part* multipart,
                              size_t multipart_len, vt_object** out_object) {
	if (out_object != NULL) {
		*out_object = NULL;
	}
	if (client == NULL || path == NULL || path[0] == '\0' ||
	    out_object == NULL) {
		return VT_INVALID_ARG;
	}

	const bool has_multipart = multipart_len > 0;
	const bool has_raw_body = body != NULL || body_len > 0;
	vt_http_request request = {
	    .method = method,
	    .path = path,
	    .body_kind = has_multipart  ? VT_HTTP_BODY_MULTIPART
	                 : has_raw_body ? VT_HTTP_BODY_RAW
	                                : VT_HTTP_BODY_NONE,
	    .body = body,
	    .body_len = body_len,
	    .content_type = content_type,
	    .multipart = multipart,
	    .multipart_len = multipart_len,
	};
	vt_http_response response = {0};

	vt_status status = vt_http_send_default(client, &request, &response);
	if (status == VT_OK) {
		status = vt_page_response_object(client, &response, out_object);
	}
	vt_http_response_cleanup(&response);
	return status;
}

vt_status vt_page_send_path_object(vt_client* client, vt_http_method method,
                                   char* path, const void* body,
                                   size_t body_len, const char* content_type,
                                   vt_object** out_object) {
	if (path == NULL) {
		return vt_page_set_error(client, VT_NOMEM,
		                         "failed to allocate request path");
	}

	const vt_status status =
	    vt_page_send_object(client, method, path, body, body_len,
	                        content_type, NULL, 0, out_object);
	free(path);
	return status;
}

vt_status vt_page_send_path_multipart(vt_client* client, vt_http_method method,
                                      char* path,
                                      const vt_http_multipart_part* multipart,
                                      size_t multipart_len,
                                      vt_object** out_object) {
	if (path == NULL) {
		return vt_page_set_error(client, VT_NOMEM,
		                         "failed to allocate request path");
	}

	const vt_status status =
	    vt_page_send_object(client, method, path, NULL, 0, NULL, multipart,
	                        multipart_len, out_object);
	free(path);
	return status;
}

vt_status vt_page_send_path_comment(vt_client* client, char* path,
                                    const char* text, vt_object** out_object) {
	if (path == NULL) {
		return vt_page_set_error(client, VT_NOMEM,
		                         "failed to allocate request path");
	}

	size_t body_len = 0;
	vt_status status = VT_OK;
	char* body = vt_json_build_comment(text, &body_len, &status);
	if (status != VT_OK) {
		free(path);
		return vt_page_set_error(client, status,
		                         "failed to build comment request");
	}

	status = vt_page_send_object(client, VT_HTTP_POST, path, body, body_len,
	                             "application/json", NULL, 0, out_object);
	vt_json_buffer_free(body);
	free(path);
	return status;
}
