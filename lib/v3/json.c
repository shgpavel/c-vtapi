/* SPDX-License-Identifier: Apache-2.0 */

#include <vt/json.h>

#define VT_JSON_INTERNAL_NO_PARSE_ALIAS 1
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

struct vt_json_doc {
	yyjson_doc* doc;
	size_t refs;
};

static void vt_json_set_status(vt_status* out, vt_status status) {
	if (out != NULL) {
		*out = status;
	}
}

static vt_status vt_json_status_from_read_error(yyjson_read_err error) {
	if (error.code == YYJSON_READ_ERROR_MEMORY_ALLOCATION) {
		return VT_NOMEM;
	}
	return VT_JSON;
}

static bool vt_json_str_eq(const char* left, const char* right) {
	return left != NULL && right != NULL && strcmp(left, right) == 0;
}

static vt_status vt_json_status_from_error_code(const char* code) {
	if (code == NULL) {
		return VT_UNKNOWN;
	}

	if (vt_json_str_eq(code, "NotFoundError")) {
		return VT_NOT_FOUND;
	}
	if (vt_json_str_eq(code, "AuthenticationRequiredError") ||
	    vt_json_str_eq(code, "ForbiddenError") ||
	    vt_json_str_eq(code, "UserNotActiveError") ||
	    vt_json_str_eq(code, "WrongCredentialsError")) {
		return VT_AUTH;
	}
	if (vt_json_str_eq(code, "QuotaExceededError") ||
	    vt_json_str_eq(code, "TooManyRequestsError")) {
		return VT_RATE_LIMIT;
	}
	if (vt_json_str_eq(code, "BadRequestError") ||
	    vt_json_str_eq(code, "InvalidArgumentError") ||
	    vt_json_str_eq(code, "InvalidQueryError")) {
		return VT_INVALID_ARG;
	}
	if (vt_json_str_eq(code, "InternalError") ||
	    vt_json_str_eq(code, "ServerError") ||
	    vt_json_str_eq(code, "ServiceUnavailableError") ||
	    vt_json_str_eq(code, "TransientError")) {
		return VT_SERVER;
	}

	return VT_UNKNOWN;
}

static yyjson_val* vt_json_root_error(yyjson_val* root) {
	if (!yyjson_is_obj(root)) {
		return NULL;
	}
	yyjson_val* error = yyjson_obj_get(root, "error");
	return yyjson_is_obj(error) ? error : NULL;
}

static const char* vt_json_error_field(yyjson_val* root, const char* field) {
	yyjson_val* error = vt_json_root_error(root);
	if (error == NULL) {
		return NULL;
	}

	yyjson_val* value = yyjson_obj_get(error, field);
	return yyjson_is_str(value) ? yyjson_get_str(value) : NULL;
}

static vt_status vt_json_error_status_from_root(yyjson_val* root) {
	if (vt_json_root_error(root) == NULL) {
		return VT_OK;
	}
	return vt_json_status_from_error_code(
	    vt_json_error_field(root, "code"));
}

static vt_json_doc* vt_json_doc_new(yyjson_doc* yy_doc) {
	vt_json_doc* doc = malloc(sizeof(*doc));
	if (doc == NULL) {
		return NULL;
	}

	doc->doc = yy_doc;
	doc->refs = 1;
	return doc;
}

vt_json_doc* vt_json_doc_ref(vt_json_doc* doc) {
	if (doc != NULL) {
		doc->refs++;
	}
	return doc;
}

void vt_json_doc_unref(vt_json_doc* doc) {
	if (doc == NULL) {
		return;
	}

	doc->refs--;
	if (doc->refs == 0) {
		yyjson_doc_free(doc->doc);
		free(doc);
	}
}

yyjson_val* vt_json_doc_root(const vt_json_doc* doc) {
	if (doc == NULL) {
		return NULL;
	}
	return yyjson_doc_get_root(doc->doc);
}

vt_json* vt_json_parse_buffer(const void* buf, size_t len, vt_status* out) {
	if (buf == NULL || len == 0) {
		vt_json_set_status(out, VT_INVALID_ARG);
		return NULL;
	}

	yyjson_read_err error = {0};
	yyjson_doc* yy_doc = yyjson_read_opts((char*)(void*)buf, len,
	                                      YYJSON_READ_NOFLAG, NULL, &error);
	if (yy_doc == NULL) {
		vt_json_set_status(out, vt_json_status_from_read_error(error));
		return NULL;
	}

	vt_json_doc* doc = vt_json_doc_new(yy_doc);
	if (doc == NULL) {
		yyjson_doc_free(yy_doc);
		vt_json_set_status(out, VT_NOMEM);
		return NULL;
	}

	vt_json* json = malloc(sizeof(*json));
	if (json == NULL) {
		vt_json_doc_unref(doc);
		vt_json_set_status(out, VT_NOMEM);
		return NULL;
	}

	json->doc = doc;
	json->stringified = NULL;

	vt_status api_status = vt_json_error_status(json);
	if (api_status != VT_OK) {
		vt_json_free(json);
		vt_json_set_status(out, api_status);
		return NULL;
	}

	vt_json_set_status(out, VT_OK);
	return json;
}

vt_status vt_json_parse(const char* input, size_t input_len,
                        vt_json** out_json) {
	if (out_json == NULL) {
		return VT_INVALID_ARG;
	}

	*out_json = NULL;
	vt_status status = VT_OK;
	vt_json* json = vt_json_parse_buffer(input, input_len, &status);
	if (status != VT_OK) {
		return status;
	}

	*out_json = json;
	return VT_OK;
}

void vt_json_free(vt_json* json) {
	if (json == NULL) {
		return;
	}

	vt_json_doc_unref(json->doc);
	free(json->stringified);
	free(json);
}

const char* vt_json_stringify(const vt_json* json) {
	if (json == NULL || json->doc == NULL) {
		return NULL;
	}

	vt_json* mutable_json = (vt_json*)json;
	if (mutable_json->stringified == NULL) {
		mutable_json->stringified =
		    yyjson_write(json->doc->doc, YYJSON_WRITE_NOFLAG, NULL);
	}

	return mutable_json->stringified;
}

vt_object* vt_json_to_object(vt_json* json) {
	if (json == NULL) {
		return NULL;
	}

	yyjson_val* root = vt_json_doc_root(json->doc);
	if (vt_json_error_status_from_root(root) != VT_OK) {
		return NULL;
	}

	yyjson_val* data =
	    yyjson_is_obj(root) ? yyjson_obj_get(root, "data") : NULL;
	if (!yyjson_is_obj(data)) {
		return NULL;
	}

	return vt_object_from_value(json->doc, data);
}

vt_iter* vt_json_to_page(vt_json* json, const vt_json_page_fetcher* fetcher,
                         vt_status* out) {
	if (json == NULL) {
		vt_json_set_status(out, VT_INVALID_ARG);
		return NULL;
	}

	yyjson_val* root = vt_json_doc_root(json->doc);
	vt_status api_status = vt_json_error_status_from_root(root);
	if (api_status != VT_OK) {
		vt_json_set_status(out, api_status);
		return NULL;
	}
	if (!yyjson_is_obj(root)) {
		vt_json_set_status(out, VT_JSON);
		return NULL;
	}

	yyjson_val* data = yyjson_obj_get(root, "data");
	if (!yyjson_is_arr(data)) {
		vt_json_set_status(out, VT_JSON);
		return NULL;
	}

	vt_iter* iter = calloc(1, sizeof(*iter));
	if (iter == NULL) {
		vt_json_set_status(out, VT_NOMEM);
		return NULL;
	}

	iter->doc = vt_json_doc_ref(json->doc);
	iter->data = data;
	iter->count = yyjson_arr_size(data);
	iter->last_error = VT_OK;
	if (fetcher != NULL) {
		iter->fetcher = *fetcher;
	}

	yyjson_val* meta = yyjson_obj_get(root, "meta");
	yyjson_val* cursor =
	    yyjson_is_obj(meta) ? yyjson_obj_get(meta, "cursor") : NULL;
	if (yyjson_is_str(cursor)) {
		iter->cursor = yyjson_get_str(cursor);
	}

	yyjson_val* links = yyjson_obj_get(root, "links");
	yyjson_val* next =
	    yyjson_is_obj(links) ? yyjson_obj_get(links, "next") : NULL;
	if (yyjson_is_str(next)) {
		iter->next_url = yyjson_get_str(next);
	}

	vt_json_set_status(out, VT_OK);
	return iter;
}

vt_status vt_json_error_status(const vt_json* json) {
	if (json == NULL) {
		return VT_INVALID_ARG;
	}

	yyjson_val* root = vt_json_doc_root(json->doc);
	if (vt_json_root_error(root) == NULL) {
		return VT_OK;
	}

	return vt_json_error_status_from_root(root);
}

const char* vt_json_error_code(const vt_json* json) {
	if (json == NULL) {
		return NULL;
	}
	return vt_json_error_field(vt_json_doc_root(json->doc), "code");
}

const char* vt_json_error_message(const vt_json* json) {
	if (json == NULL) {
		return NULL;
	}
	return vt_json_error_field(vt_json_doc_root(json->doc), "message");
}

char* vt_json_build_comment(const char* text, size_t* out_len, vt_status* out) {
	if (out_len != NULL) {
		*out_len = 0;
	}
	if (text == NULL) {
		vt_json_set_status(out, VT_INVALID_ARG);
		return NULL;
	}

	yyjson_mut_doc* doc = yyjson_mut_doc_new(NULL);
	if (doc == NULL) {
		vt_json_set_status(out, VT_NOMEM);
		return NULL;
	}

	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_val* data = yyjson_mut_obj(doc);
	yyjson_mut_val* attributes = yyjson_mut_obj(doc);
	if (root == NULL || data == NULL || attributes == NULL) {
		yyjson_mut_doc_free(doc);
		vt_json_set_status(out, VT_NOMEM);
		return NULL;
	}

	yyjson_mut_doc_set_root(doc, root);
	bool ok = yyjson_mut_obj_add_val(doc, root, "data", data) &&
	          yyjson_mut_obj_add_str(doc, data, "type", "comment") &&
	          yyjson_mut_obj_add_val(doc, data, "attributes", attributes) &&
	          yyjson_mut_obj_add_strcpy(doc, attributes, "text", text);
	if (!ok) {
		yyjson_mut_doc_free(doc);
		vt_json_set_status(out, VT_NOMEM);
		return NULL;
	}

	size_t len = 0;
	yyjson_write_err error = {0};
	char* buffer =
	    yyjson_mut_write_opts(doc, YYJSON_WRITE_NOFLAG, NULL, &len, &error);
	yyjson_mut_doc_free(doc);
	if (buffer == NULL) {
		vt_json_set_status(
		    out, error.code == YYJSON_WRITE_ERROR_MEMORY_ALLOCATION
		             ? VT_NOMEM
		             : VT_JSON);
		return NULL;
	}

	if (out_len != NULL) {
		*out_len = len;
	}
	vt_json_set_status(out, VT_OK);
	return buffer;
}

void vt_json_buffer_free(char* buffer) {
	free(buffer);
}
