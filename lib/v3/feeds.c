/* SPDX-License-Identifier: Apache-2.0 */

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vt/feeds.h>

#include "http.h"

static bool is_empty(const char* value) {
	return value == NULL || value[0] == '\0';
}

static bool is_feed_time(const char* value) {
	if (value == NULL) {
		return false;
	}

	for (size_t i = 0; i < 12; i++) {
		if (value[i] == '\0' || isdigit((unsigned char)value[i]) == 0) {
			return false;
		}
	}

	return value[12] == '\0';
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

static char* feed_path(const char* feed, const char* time_param) {
	char* escaped_time = path_escape(time_param);
	if (escaped_time == NULL) {
		return NULL;
	}

	const int needed =
	    snprintf(NULL, 0, "/feeds/%s/%s", feed, escaped_time);
	if (needed < 0) {
		free(escaped_time);
		return NULL;
	}

	char* path = malloc((size_t)needed + 1);
	if (path == NULL) {
		free(escaped_time);
		return NULL;
	}

	snprintf(path, (size_t)needed + 1, "/feeds/%s/%s", feed, escaped_time);
	free(escaped_time);
	return path;
}

static char* feed_file_path(const char* time_param, const char* sha256) {
	char* escaped_time = path_escape(time_param);
	char* escaped_sha256 = path_escape(sha256);
	if (escaped_time == NULL || escaped_sha256 == NULL) {
		free(escaped_time);
		free(escaped_sha256);
		return NULL;
	}

	const int needed = snprintf(NULL, 0, "/feeds/files/%s/%s", escaped_time,
	                            escaped_sha256);
	if (needed < 0) {
		free(escaped_time);
		free(escaped_sha256);
		return NULL;
	}

	char* path = malloc((size_t)needed + 1);
	if (path == NULL) {
		free(escaped_time);
		free(escaped_sha256);
		return NULL;
	}

	snprintf(path, (size_t)needed + 1, "/feeds/files/%s/%s", escaped_time,
	         escaped_sha256);
	free(escaped_time);
	free(escaped_sha256);
	return path;
}

static vt_status fetch_raw_feed(vt_client* client, char* path, void** out_buf,
                                size_t* out_len) {
	if (path == NULL) {
		return vt_client_set_error(client, VT_NOMEM,
		                           "failed to allocate request path");
	}

	vt_http_request request = {
	    .method = VT_HTTP_GET,
	    .path = path,
	};
	vt_http_response response = {0};
	vt_status status = vt_http_send_default(client, &request, &response);
	free(path);
	if (status != VT_OK) {
		vt_http_response_cleanup(&response);
		return status;
	}

	*out_buf = response.body;
	*out_len = response.body_len;
	response.body = NULL;
	response.body_len = 0;
	vt_http_response_cleanup(&response);
	return VT_OK;
}

vt_status vt_feeds_files(vt_client* client, const char* time_param,
                         void** out_buf, size_t* out_len) {
	if (out_buf != NULL) {
		*out_buf = NULL;
	}
	if (out_len != NULL) {
		*out_len = 0;
	}
	if (client == NULL || !is_feed_time(time_param) || out_buf == NULL ||
	    out_len == NULL) {
		return VT_INVALID_ARG;
	}

	return fetch_raw_feed(client, feed_path("files", time_param), out_buf,
	                      out_len);
}

vt_status vt_feeds_urls(vt_client* client, const char* time_param,
                        void** out_buf, size_t* out_len) {
	if (out_buf != NULL) {
		*out_buf = NULL;
	}
	if (out_len != NULL) {
		*out_len = 0;
	}
	if (client == NULL || !is_feed_time(time_param) || out_buf == NULL ||
	    out_len == NULL) {
		return VT_INVALID_ARG;
	}

	return fetch_raw_feed(client, feed_path("urls", time_param), out_buf,
	                      out_len);
}

vt_status vt_feeds_file_for(vt_client* client, const char* time_param,
                            const char* sha256, void** out_buf,
                            size_t* out_len) {
	if (out_buf != NULL) {
		*out_buf = NULL;
	}
	if (out_len != NULL) {
		*out_len = 0;
	}
	if (client == NULL || !is_feed_time(time_param) || is_empty(sha256) ||
	    out_buf == NULL || out_len == NULL) {
		return VT_INVALID_ARG;
	}

	return fetch_raw_feed(client, feed_file_path(time_param, sha256),
	                      out_buf, out_len);
}
