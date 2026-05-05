/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_V3_HTTP_H
#define VT_V3_HTTP_H 1

#include <stddef.h>
#include <vt/client.h>
#include <vt/error.h>

struct vt_http_request {
	const char* method;
	const char* path;
	const void* body;
	size_t body_len;
};

struct vt_http_response {
	long status_code;
	char* body;
	size_t body_len;
};

vt_status vt_http_send_default(vt_client* client,
                               const vt_http_request* request,
                               vt_http_response* response);

#endif /* VT_V3_HTTP_H */
