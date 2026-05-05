/* SPDX-License-Identifier: Apache-2.0 */

#include "http.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

#define VT_HTTP_INITIAL_BACKOFF_MS 250ULL

typedef struct vt_http_buffer {
	char* data;
	size_t len;
} vt_http_buffer;

typedef struct vt_http_header_ctx {
	vt_http_response* response;
} vt_http_header_ctx;

static char* vt_http_strdup(const char* value) {
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

static char* vt_http_dup_range(const char* start, size_t len) {
	char* copy = malloc(len + 1);
	if (copy == NULL) {
		return NULL;
	}

	memcpy(copy, start, len);
	copy[len] = '\0';
	return copy;
}

static bool vt_http_has_prefix(const char* value, const char* prefix) {
	return strncmp(value, prefix, strlen(prefix)) == 0;
}

static bool vt_http_path_is_absolute(const char* path) {
	return vt_http_has_prefix(path, "https://") ||
	       vt_http_has_prefix(path, "http://");
}

static bool vt_http_header_name_eq(const char* actual, size_t actual_len,
                                   const char* expected) {
	const size_t expected_len = strlen(expected);
	if (actual_len != expected_len) {
		return false;
	}

	for (size_t i = 0; i < actual_len; i++) {
		const unsigned char lhs = (unsigned char)actual[i];
		const unsigned char rhs = (unsigned char)expected[i];
		if (tolower(lhs) != tolower(rhs)) {
			return false;
		}
	}

	return true;
}

static vt_status vt_http_append(char** out, const char* suffix) {
	if (out == NULL || *out == NULL || suffix == NULL) {
		return VT_INVALID_ARG;
	}

	const size_t lhs_len = strlen(*out);
	const size_t rhs_len = strlen(suffix);
	if (SIZE_MAX - lhs_len <= rhs_len) {
		return VT_NOMEM;
	}

	char* combined = realloc(*out, lhs_len + rhs_len + 1);
	if (combined == NULL) {
		return VT_NOMEM;
	}

	memcpy(combined + lhs_len, suffix, rhs_len + 1);
	*out = combined;
	return VT_OK;
}

static vt_status vt_http_append_query_param(CURL* easy, char** url,
                                            bool* has_query,
                                            const vt_http_query_param* param) {
	if (param->name == NULL || param->name[0] == '\0') {
		return VT_INVALID_ARG;
	}

	char* escaped_name = curl_easy_escape(easy, param->name, 0);
	char* escaped_value =
	    curl_easy_escape(easy, param->value == NULL ? "" : param->value, 0);
	if (escaped_name == NULL || escaped_value == NULL) {
		curl_free(escaped_name);
		curl_free(escaped_value);
		return VT_NOMEM;
	}

	vt_status status = vt_http_append(url, *has_query ? "&" : "?");
	if (status == VT_OK) {
		status = vt_http_append(url, escaped_name);
	}
	if (status == VT_OK) {
		status = vt_http_append(url, "=");
	}
	if (status == VT_OK) {
		status = vt_http_append(url, escaped_value);
	}

	curl_free(escaped_name);
	curl_free(escaped_value);
	if (status == VT_OK) {
		*has_query = true;
	}
	return status;
}

static vt_status vt_http_build_url(vt_client* client,
                                   const vt_http_request* request,
                                   char** out_url) {
	if (request->path == NULL || request->path[0] == '\0') {
		return VT_INVALID_ARG;
	}

	char* url = NULL;
	if (vt_http_path_is_absolute(request->path)) {
		url = vt_http_strdup(request->path);
	} else {
		const char* separator = request->path[0] == '/' ? "" : "/";
		const int len = snprintf(NULL, 0, "%s%s%s", client->base_url,
		                         separator, request->path);
		if (len < 0) {
			return VT_UNKNOWN;
		}
		url = malloc((size_t)len + 1);
		if (url != NULL) {
			snprintf(url, (size_t)len + 1, "%s%s%s",
			         client->base_url, separator, request->path);
		}
	}
	if (url == NULL) {
		return VT_NOMEM;
	}

	bool has_query = strchr(url, '?') != NULL;
	for (size_t i = 0; i < request->query_len; i++) {
		const vt_status status = vt_http_append_query_param(
		    client->easy, &url, &has_query, &request->query[i]);
		if (status != VT_OK) {
			free(url);
			return status;
		}
	}

	*out_url = url;
	return VT_OK;
}

static size_t vt_http_write_body(char* ptr, size_t size, size_t nmemb,
                                 void* userdata) {
	if (size != 0 && nmemb > SIZE_MAX / size) {
		return 0;
	}
	const size_t incoming = size * nmemb;
	vt_http_buffer* buffer = userdata;
	if (incoming == 0) {
		return 0;
	}
	if (SIZE_MAX - buffer->len <= incoming) {
		return 0;
	}

	char* data = realloc(buffer->data, buffer->len + incoming + 1);
	if (data == NULL) {
		return 0;
	}

	memcpy(data + buffer->len, ptr, incoming);
	buffer->len += incoming;
	data[buffer->len] = '\0';
	buffer->data = data;
	return incoming;
}

static void vt_http_replace_header_value(char** slot, const char* value,
                                         size_t value_len) {
	char* copy = vt_http_dup_range(value, value_len);
	if (copy == NULL) {
		return;
	}

	free(*slot);
	*slot = copy;
}

static size_t vt_http_header(char* ptr, size_t size, size_t nmemb,
                             void* userdata) {
	if (size != 0 && nmemb > SIZE_MAX / size) {
		return 0;
	}
	const size_t line_len = size * nmemb;
	vt_http_header_ctx* ctx = userdata;
	if (line_len == 0 || ctx == NULL || ctx->response == NULL) {
		return line_len;
	}

	const char* colon = memchr(ptr, ':', line_len);
	if (colon == NULL) {
		return line_len;
	}

	const char* name = ptr;
	size_t name_len = (size_t)(colon - ptr);
	while (name_len > 0 &&
	       isspace((unsigned char)name[name_len - 1]) != 0) {
		name_len--;
	}

	const char* value = colon + 1;
	const char* end = ptr + line_len;
	while (value < end && isspace((unsigned char)*value) != 0) {
		value++;
	}
	while (end > value && isspace((unsigned char)*(end - 1)) != 0) {
		end--;
	}
	const size_t value_len = (size_t)(end - value);

	if (vt_http_header_name_eq(name, name_len, "content-type")) {
		vt_http_replace_header_value(&ctx->response->content_type,
		                             value, value_len);
	} else if (vt_http_header_name_eq(name, name_len, "retry-after")) {
		vt_http_replace_header_value(&ctx->response->retry_after, value,
		                             value_len);
	} else if (vt_http_header_name_eq(name, name_len, "location")) {
		vt_http_replace_header_value(&ctx->response->location, value,
		                             value_len);
	} else if (vt_http_header_name_eq(name, name_len, "link")) {
		vt_http_replace_header_value(&ctx->response->link, value,
		                             value_len);
	}

	return line_len;
}

static vt_status vt_http_append_header(struct curl_slist** headers,
                                       const char* value) {
	struct curl_slist* next = curl_slist_append(*headers, value);
	if (next == NULL) {
		return VT_NOMEM;
	}

	*headers = next;
	return VT_OK;
}

static vt_status vt_http_add_header_value(struct curl_slist** headers,
                                          const char* name, const char* value) {
	const int len = snprintf(NULL, 0, "%s: %s", name, value);
	if (len < 0) {
		return VT_UNKNOWN;
	}

	char* header = malloc((size_t)len + 1);
	if (header == NULL) {
		return VT_NOMEM;
	}

	snprintf(header, (size_t)len + 1, "%s: %s", name, value);
	const vt_status status = vt_http_append_header(headers, header);
	free(header);
	return status;
}

static const char* vt_http_method_name(vt_http_method method) {
	switch (method) {
		case VT_HTTP_GET:
			return "GET";
		case VT_HTTP_POST:
			return "POST";
		case VT_HTTP_DELETE:
			return "DELETE";
		case VT_HTTP_PATCH:
			return "PATCH";
		case VT_HTTP_PUT:
			return "PUT";
		default:
			return NULL;
	}
}

static vt_http_body_kind vt_http_effective_body_kind(
    const vt_http_request* request) {
	if (request->multipart_len > 0) {
		return VT_HTTP_BODY_MULTIPART;
	}
	if (request->body_kind == VT_HTTP_BODY_NONE &&
	    (request->body != NULL || request->body_len > 0)) {
		return VT_HTTP_BODY_RAW;
	}

	return request->body_kind;
}

static vt_status vt_http_configure_method(CURL* easy,
                                          const vt_http_request* request) {
	const char* method = vt_http_method_name(request->method);
	if (method == NULL) {
		return VT_INVALID_ARG;
	}

	const vt_http_body_kind body_kind =
	    vt_http_effective_body_kind(request);
	if (request->method == VT_HTTP_GET && body_kind != VT_HTTP_BODY_NONE) {
		return VT_INVALID_ARG;
	}
	if (body_kind == VT_HTTP_BODY_RAW && request->body == NULL &&
	    request->body_len > 0) {
		return VT_INVALID_ARG;
	}

	switch (request->method) {
		case VT_HTTP_GET:
			curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
			break;
		case VT_HTTP_POST:
			curl_easy_setopt(easy, CURLOPT_POST, 1L);
			break;
		case VT_HTTP_DELETE:
		case VT_HTTP_PATCH:
		case VT_HTTP_PUT:
			curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, method);
			break;
		default:
			return VT_INVALID_ARG;
	}

	if (body_kind == VT_HTTP_BODY_RAW) {
		curl_easy_setopt(easy, CURLOPT_POSTFIELDS,
		                 request->body == NULL ? "" : request->body);
		curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE,
		                 (curl_off_t)request->body_len);
	}

	return VT_OK;
}

static vt_status vt_http_configure_multipart(CURL* easy,
                                             const vt_http_request* request,
                                             curl_mime** out_mime) {
	if (vt_http_effective_body_kind(request) != VT_HTTP_BODY_MULTIPART) {
		*out_mime = NULL;
		return VT_OK;
	}
	if (request->multipart == NULL || request->multipart_len == 0) {
		return VT_INVALID_ARG;
	}

	curl_mime* mime = curl_mime_init(easy);
	if (mime == NULL) {
		return VT_NOMEM;
	}

	for (size_t i = 0; i < request->multipart_len; i++) {
		const vt_http_multipart_part* request_part =
		    &request->multipart[i];
		if (request_part->name == NULL ||
		    request_part->name[0] == '\0') {
			curl_mime_free(mime);
			return VT_INVALID_ARG;
		}

		curl_mimepart* part = curl_mime_addpart(mime);
		if (part == NULL ||
		    curl_mime_name(part, request_part->name) != CURLE_OK) {
			curl_mime_free(mime);
			return VT_NOMEM;
		}

		CURLcode curl_status = CURLE_OK;
		if (request_part->source == VT_HTTP_MULTIPART_FILE) {
			if (request_part->path == NULL) {
				curl_mime_free(mime);
				return VT_INVALID_ARG;
			}
			curl_status =
			    curl_mime_filedata(part, request_part->path);
		} else {
			if (request_part->data == NULL &&
			    request_part->data_len > 0) {
				curl_mime_free(mime);
				return VT_INVALID_ARG;
			}
			const char* data =
			    request_part->data == NULL
			        ? ""
			        : (const char*)request_part->data;
			curl_status =
			    curl_mime_data(part, data, request_part->data_len);
		}
		if (curl_status != CURLE_OK) {
			curl_mime_free(mime);
			return VT_NOMEM;
		}

		if (request_part->filename != NULL &&
		    curl_mime_filename(part, request_part->filename) !=
		        CURLE_OK) {
			curl_mime_free(mime);
			return VT_NOMEM;
		}
		if (request_part->content_type != NULL &&
		    curl_mime_type(part, request_part->content_type) !=
		        CURLE_OK) {
			curl_mime_free(mime);
			return VT_NOMEM;
		}
	}

	curl_easy_setopt(easy, CURLOPT_MIMEPOST, mime);
	*out_mime = mime;
	return VT_OK;
}

static uint64_t vt_http_retry_after_ms(const char* retry_after) {
	if (retry_after == NULL || retry_after[0] == '\0') {
		return 0;
	}

	errno = 0;
	char* end = NULL;
	const unsigned long seconds = strtoul(retry_after, &end, 10);
	while (end != NULL && *end != '\0' &&
	       isspace((unsigned char)*end) != 0) {
		end++;
	}
	if (errno == 0 && end != retry_after && end != NULL && *end == '\0') {
		return (uint64_t)seconds * 1000ULL;
	}

	const time_t retry_time = curl_getdate(retry_after, NULL);
	if (retry_time == (time_t)-1) {
		return 0;
	}

	const time_t now = time(NULL);
	if (retry_time <= now) {
		return 0;
	}

	return (uint64_t)(retry_time - now) * 1000ULL;
}

static uint64_t vt_http_backoff_ms(unsigned int retry_index) {
	uint64_t delay = VT_HTTP_INITIAL_BACKOFF_MS;
	for (unsigned int i = 0; i < retry_index && delay < 1000ULL; i++) {
		delay *= 2ULL;
	}
	if (delay > 1000ULL) {
		delay = 1000ULL;
	}

	const uint64_t jitter = (uint64_t)((retry_index * 37U) % 125U);
	return delay + jitter;
}

static void vt_http_sleep_ms(uint64_t delay_ms) {
	if (delay_ms == 0) {
		return;
	}

	const struct timespec delay = {
	    .tv_sec = (time_t)(delay_ms / 1000ULL),
	    .tv_nsec = (long)((delay_ms % 1000ULL) * 1000000ULL),
	};
	(void)thrd_sleep(&delay, NULL);
}

static bool vt_http_should_retry(const vt_http_response* response,
                                 unsigned int retry_index,
                                 unsigned int max_retries,
                                 uint64_t* out_delay_ms) {
	if (retry_index >= max_retries) {
		return false;
	}

	if (response->status_code == 429) {
		uint64_t delay = vt_http_retry_after_ms(response->retry_after);
		if (delay == 0) {
			delay = vt_http_backoff_ms(retry_index);
		}
		*out_delay_ms = delay;
		return true;
	}

	if (response->status_code >= 500 && response->status_code <= 599) {
		*out_delay_ms = vt_http_backoff_ms(retry_index);
		return true;
	}

	return false;
}

static vt_status vt_http_setup_common(
    vt_client* client, const vt_http_request* request,
    vt_http_response* response, vt_http_buffer* body,
    vt_http_header_ctx* header_ctx, struct curl_slist** headers,
    curl_mime** mime, const char* url, char* error_buffer) {
	curl_easy_reset(client->easy);
	error_buffer[0] = '\0';

	vt_status status =
	    vt_http_add_header_value(headers, "x-apikey", client->api_key);
	if (status == VT_OK) {
		status =
		    vt_http_append_header(headers, "accept: application/json");
	}
	if (status == VT_OK &&
	    vt_http_effective_body_kind(request) == VT_HTTP_BODY_RAW &&
	    request->content_type != NULL) {
		status = vt_http_add_header_value(headers, "content-type",
		                                  request->content_type);
	}
	if (status != VT_OK) {
		return status;
	}

	curl_easy_setopt(client->easy, CURLOPT_URL, url);
	curl_easy_setopt(client->easy, CURLOPT_HTTPHEADER, *headers);
	curl_easy_setopt(client->easy, CURLOPT_USERAGENT, client->user_agent);
	curl_easy_setopt(client->easy, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(client->easy, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(client->easy, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(client->easy, CURLOPT_ERRORBUFFER, error_buffer);
	curl_easy_setopt(client->easy, CURLOPT_WRITEFUNCTION,
	                 vt_http_write_body);
	curl_easy_setopt(client->easy, CURLOPT_WRITEDATA, body);
	curl_easy_setopt(client->easy, CURLOPT_HEADERFUNCTION, vt_http_header);
	curl_easy_setopt(client->easy, CURLOPT_HEADERDATA, header_ctx);
	if (client->timeout_ms > 0) {
		curl_easy_setopt(client->easy, CURLOPT_TIMEOUT_MS,
		                 (long)client->timeout_ms);
	}

	status = vt_http_configure_method(client->easy, request);
	if (status != VT_OK) {
		return status;
	}

	status = vt_http_configure_multipart(client->easy, request, mime);
	if (status != VT_OK) {
		return status;
	}

	response->status_code = 0;
	return VT_OK;
}

void vt_http_response_cleanup(vt_http_response* response) {
	if (response == NULL) {
		return;
	}

	free(response->content_type);
	free(response->retry_after);
	free(response->location);
	free(response->link);
	free(response->body);
	memset(response, 0, sizeof(*response));
}

vt_status vt_http_send_default(vt_client* client,
                               const vt_http_request* request,
                               vt_http_response* response) {
	if (client == NULL || request == NULL || response == NULL ||
	    client->easy == NULL) {
		return vt_client_set_error(client, VT_INVALID_ARG,
		                           "request and response are required");
	}
	memset(response, 0, sizeof(*response));

	char* url = NULL;
	vt_status status = vt_http_build_url(client, request, &url);
	if (status != VT_OK) {
		return vt_client_set_error(client, status,
		                           "failed to build request URL");
	}

	unsigned int retry_index = 0;
	for (;;) {
		vt_http_response_cleanup(response);
		vt_http_buffer body = {0};
		vt_http_header_ctx header_ctx = {.response = response};
		struct curl_slist* headers = NULL;
		curl_mime* mime = NULL;
		char error_buffer[CURL_ERROR_SIZE] = {0};

		status = vt_http_setup_common(client, request, response, &body,
		                              &header_ctx, &headers, &mime, url,
		                              error_buffer);
		if (status != VT_OK) {
			free(body.data);
			curl_mime_free(mime);
			curl_slist_free_all(headers);
			free(url);
			return vt_client_set_error(
			    client, status, "failed to configure request");
		}

		const CURLcode curl_status = curl_easy_perform(client->easy);
		response->body = body.data;
		response->body_len = body.len;

		if (curl_status == CURLE_OK) {
			curl_easy_getinfo(client->easy, CURLINFO_RESPONSE_CODE,
			                  &response->status_code);
		}

		curl_mime_free(mime);
		curl_slist_free_all(headers);

		if (curl_status != CURLE_OK) {
			free(url);
			const char* detail =
			    error_buffer[0] != '\0'
			        ? error_buffer
			        : curl_easy_strerror(curl_status);
			return vt_client_set_errorf(
			    client, VT_NETWORK, "network error: %s", detail);
		}

		uint64_t delay_ms = 0;
		if (!vt_http_should_retry(response, retry_index,
		                          client->max_retries, &delay_ms)) {
			break;
		}

		retry_index++;
		vt_http_sleep_ms(delay_ms);
	}

	free(url);

	status = vt_http_status_to_vt_status(response->status_code);
	if (status != VT_OK) {
		if (response->body != NULL && response->body[0] != '\0') {
			return vt_client_set_errorf(
			    client, status, "HTTP %ld: %s",
			    response->status_code, response->body);
		}
		return vt_client_set_errorf(client, status, "HTTP %ld",
		                            response->status_code);
	}

	vt_client_clear_error(client);
	return VT_OK;
}
