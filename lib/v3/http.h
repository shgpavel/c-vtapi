/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_V3_HTTP_H
#define VT_V3_HTTP_H 1

#include <curl/curl.h>
#include <stddef.h>
#include <stdint.h>
#include <vt/client.h>
#include <vt/error.h>
#include <vt/iter.h>
#include <vt/object.h>

#define VT_HTTP_DEFAULT_BASE_URL "https://www.virustotal.com/api/v3"
#define VT_HTTP_DEFAULT_MAX_RETRIES 3U
#define VT_HTTP_PACKAGE_VERSION "0.1.0"

typedef enum vt_http_method {
	VT_HTTP_GET = 0,
	VT_HTTP_POST,
	VT_HTTP_DELETE,
	VT_HTTP_PATCH,
	VT_HTTP_PUT,
} vt_http_method;

typedef struct vt_http_query_param {
	const char* name;
	const char* value;
} vt_http_query_param;

typedef enum vt_http_body_kind {
	VT_HTTP_BODY_NONE = 0,
	VT_HTTP_BODY_RAW,
	VT_HTTP_BODY_MULTIPART,
} vt_http_body_kind;

typedef enum vt_http_multipart_source {
	VT_HTTP_MULTIPART_DATA = 0,
	VT_HTTP_MULTIPART_FILE,
} vt_http_multipart_source;

typedef struct vt_http_multipart_part {
	const char* name;
	const char* filename;
	const char* content_type;
	vt_http_multipart_source source;
	const char* path;
	const void* data;
	size_t data_len;
} vt_http_multipart_part;

struct vt_http_request {
	vt_http_method method;
	const char* path;
	const vt_http_query_param* query;
	size_t query_len;
	vt_http_body_kind body_kind;
	const void* body;
	size_t body_len;
	const char* content_type;
	const vt_http_multipart_part* multipart;
	size_t multipart_len;
};

struct vt_http_response {
	long status_code;
	char* content_type;
	char* retry_after;
	char* location;
	char* link;
	char* body;
	size_t body_len;
};

struct vt_client {
	CURL* easy;
	char* api_key;
	char* base_url;
	char* user_agent;
	uint64_t timeout_ms;
	unsigned int max_retries;
	vt_http_send_fn transport_send;
	void* transport_userdata;
	char* last_error;
};

typedef vt_status (*vt_iter_parse_page_fn)(const vt_http_response* response,
                                           vt_object*** out_objects,
                                           size_t* out_count,
                                           char** out_next_url,
                                           char** out_cursor, void* userdata);

vt_status vt_client_send(vt_client* client, const vt_http_request* request,
                         vt_http_response* response);
vt_status vt_client_set_max_retries(vt_client* client,
                                    unsigned int max_retries);
void vt_client_clear_error(vt_client* client);
vt_status vt_client_set_error(vt_client* client, vt_status status,
                              const char* message);
vt_status vt_client_set_errorf(vt_client* client, vt_status status,
                               const char* format, ...);

vt_status vt_http_status_to_vt_status(long status_code);
vt_status vt_http_send_default(vt_client* client,
                               const vt_http_request* request,
                               vt_http_response* response);
void vt_http_response_cleanup(vt_http_response* response);

vt_status vt_iter_new(vt_client* client, const char* initial_url,
                      vt_iter_parse_page_fn parse_page, void* userdata,
                      vt_iter** out_iter);

#endif /* VT_V3_HTTP_H */
