/* SPDX-License-Identifier: Apache-2.0 */

#include "http.h"

#include <stddef.h>

vt_status vt_http_send_default(vt_client* client,
                               const vt_http_request* request,
                               vt_http_response* response) {
	(void)client;
	(void)request;
	(void)response;
	/* TODO: Implement the default libcurl-backed HTTP transport. */
	return VT_UNIMPL;
}
