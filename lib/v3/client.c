/* SPDX-License-Identifier: Apache-2.0 */

#include <curl/curl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <pthread.h>
#endif

#include "http.h"

#if !defined(_WIN32)
static pthread_mutex_t vt_curl_global_mutex = PTHREAD_MUTEX_INITIALIZER;
#define VT_CURL_GLOBAL_LOCK() pthread_mutex_lock(&vt_curl_global_mutex)
#define VT_CURL_GLOBAL_UNLOCK() pthread_mutex_unlock(&vt_curl_global_mutex)
#else
#define VT_CURL_GLOBAL_LOCK() ((void)0)
#define VT_CURL_GLOBAL_UNLOCK() ((void)0)
#endif

static unsigned int vt_curl_global_refcount;

static char* vt_client_strdup(const char* value) {
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

static char* vt_client_strdup_base_url(const char* value) {
	if (value == NULL || value[0] == '\0') {
		return NULL;
	}

	size_t len = strlen(value);
	while (len > 0 && value[len - 1] == '/') {
		len--;
	}
	if (len == 0) {
		return NULL;
	}

	char* copy = malloc(len + 1);
	if (copy == NULL) {
		return NULL;
	}

	memcpy(copy, value, len);
	copy[len] = '\0';
	return copy;
}

static vt_status vt_curl_global_acquire(void) {
	VT_CURL_GLOBAL_LOCK();
	if (vt_curl_global_refcount == 0) {
		const CURLcode curl_status =
		    curl_global_init(CURL_GLOBAL_DEFAULT);
		if (curl_status != CURLE_OK) {
			VT_CURL_GLOBAL_UNLOCK();
			return VT_NETWORK;
		}
	}

	vt_curl_global_refcount++;
	VT_CURL_GLOBAL_UNLOCK();
	return VT_OK;
}

static void vt_curl_global_release(void) {
	VT_CURL_GLOBAL_LOCK();
	if (vt_curl_global_refcount == 0) {
		VT_CURL_GLOBAL_UNLOCK();
		return;
	}

	vt_curl_global_refcount--;
	if (vt_curl_global_refcount == 0) {
		curl_global_cleanup();
	}
	VT_CURL_GLOBAL_UNLOCK();
}

static char* vt_client_default_user_agent(void) {
	const curl_version_info_data* curl_info =
	    curl_version_info(CURLVERSION_NOW);
	const char* curl_version =
	    curl_info != NULL && curl_info->version != NULL ? curl_info->version
	                                                    : "unknown";
	const int len = snprintf(NULL, 0, "c-vtapi/%s libcurl/%s",
	                         VT_HTTP_PACKAGE_VERSION, curl_version);
	if (len < 0) {
		return NULL;
	}

	char* user_agent = malloc((size_t)len + 1);
	if (user_agent == NULL) {
		return NULL;
	}

	snprintf(user_agent, (size_t)len + 1, "c-vtapi/%s libcurl/%s",
	         VT_HTTP_PACKAGE_VERSION, curl_version);
	return user_agent;
}

vt_client* vt_client_new(const char* api_key) {
	if (api_key == NULL || api_key[0] == '\0') {
		return NULL;
	}

	if (vt_curl_global_acquire() != VT_OK) {
		return NULL;
	}

	vt_client* client = calloc(1, sizeof(*client));
	if (client == NULL) {
		vt_curl_global_release();
		return NULL;
	}

	client->easy = curl_easy_init();
	client->api_key = vt_client_strdup(api_key);
	client->base_url = vt_client_strdup_base_url(VT_HTTP_DEFAULT_BASE_URL);
	client->user_agent = vt_client_default_user_agent();
	client->max_retries = VT_HTTP_DEFAULT_MAX_RETRIES;

	if (client->easy == NULL || client->api_key == NULL ||
	    client->base_url == NULL || client->user_agent == NULL) {
		vt_client_free(client);
		return NULL;
	}

	return client;
}

void vt_client_free(vt_client* client) {
	if (client == NULL) {
		return;
	}

	if (client->easy != NULL) {
		curl_easy_cleanup(client->easy);
	}

	free(client->api_key);
	free(client->base_url);
	free(client->user_agent);
	free(client->last_error);
	free(client);
	vt_curl_global_release();
}

vt_status vt_client_set_base_url(vt_client* client, const char* base_url) {
	if (client == NULL || base_url == NULL || base_url[0] == '\0') {
		return vt_client_set_error(client, VT_INVALID_ARG,
		                           "base URL is required");
	}

	char* copy = vt_client_strdup_base_url(base_url);
	if (copy == NULL) {
		return vt_client_set_error(client, VT_NOMEM,
		                           "failed to store base URL");
	}

	free(client->base_url);
	client->base_url = copy;
	vt_client_clear_error(client);
	return VT_OK;
}

vt_status vt_client_set_user_agent(vt_client* client, const char* user_agent) {
	if (client == NULL || user_agent == NULL || user_agent[0] == '\0') {
		return vt_client_set_error(client, VT_INVALID_ARG,
		                           "User-Agent is required");
	}

	char* copy = vt_client_strdup(user_agent);
	if (copy == NULL) {
		return vt_client_set_error(client, VT_NOMEM,
		                           "failed to store User-Agent");
	}

	free(client->user_agent);
	client->user_agent = copy;
	vt_client_clear_error(client);
	return VT_OK;
}

vt_status vt_client_set_timeout_ms(vt_client* client, uint64_t timeout_ms) {
	if (client == NULL) {
		return vt_client_set_error(client, VT_INVALID_ARG,
		                           "client is required");
	}
	if (timeout_ms > (uint64_t)LONG_MAX) {
		return vt_client_set_error(client, VT_INVALID_ARG,
		                           "timeout is too large");
	}

	client->timeout_ms = timeout_ms;
	vt_client_clear_error(client);
	return VT_OK;
}

vt_status vt_client_set_transport(vt_client* client, vt_http_send_fn send,
                                  void* userdata) {
	if (client == NULL) {
		return vt_client_set_error(client, VT_INVALID_ARG,
		                           "client is required");
	}

	client->transport_send = send;
	client->transport_userdata = send == NULL ? NULL : userdata;
	vt_client_clear_error(client);
	return VT_OK;
}

vt_status vt_client_set_max_retries(vt_client* client,
                                    unsigned int max_retries) {
	if (client == NULL) {
		return vt_client_set_error(client, VT_INVALID_ARG,
		                           "client is required");
	}

	client->max_retries = max_retries;
	vt_client_clear_error(client);
	return VT_OK;
}

vt_status vt_client_send(vt_client* client, const vt_http_request* request,
                         vt_http_response* response) {
	if (response != NULL) {
		memset(response, 0, sizeof(*response));
	}
	if (client == NULL || request == NULL || response == NULL) {
		return vt_client_set_error(client, VT_INVALID_ARG,
		                           "request and response are required");
	}

	vt_client_clear_error(client);
	if (client->transport_send != NULL) {
		return client->transport_send(client, request, response,
		                              client->transport_userdata);
	}

	return vt_http_send_default(client, request, response);
}

void vt_client_clear_error(vt_client* client) {
	if (client == NULL) {
		return;
	}

	free(client->last_error);
	client->last_error = NULL;
}

vt_status vt_client_set_error(vt_client* client, vt_status status,
                              const char* message) {
	if (client == NULL) {
		return status;
	}

	char* copy = NULL;
	if (message != NULL) {
		copy = vt_client_strdup(message);
		if (copy == NULL) {
			free(client->last_error);
			client->last_error = NULL;
			return VT_NOMEM;
		}
	}

	free(client->last_error);
	client->last_error = copy;
	return status;
}

vt_status vt_client_set_errorf(vt_client* client, vt_status status,
                               const char* format, ...) {
	if (client == NULL || format == NULL) {
		return status;
	}

	va_list args;
	va_start(args, format);
	va_list args_copy;
	va_copy(args_copy, args);
	const int len = vsnprintf(NULL, 0, format, args_copy);
	va_end(args_copy);
	if (len < 0) {
		va_end(args);
		return vt_client_set_error(client, status,
		                           vt_status_str(status));
	}

	char* message = malloc((size_t)len + 1);
	if (message == NULL) {
		va_end(args);
		return vt_client_set_error(client, VT_NOMEM,
		                           "failed to store error message");
	}

	vsnprintf(message, (size_t)len + 1, format, args);
	va_end(args);

	free(client->last_error);
	client->last_error = message;
	return status;
}
