/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/error.h>

const char* vt_status_str(vt_status status) {
	switch (status) {
		case VT_OK:
			return "ok";
		case VT_INVALID_ARG:
			return "invalid argument";
		case VT_AUTH:
			return "authentication error";
		case VT_NOT_FOUND:
			return "not found";
		case VT_RATE_LIMIT:
			return "rate limit";
		case VT_SERVER:
			return "server error";
		case VT_NETWORK:
			return "network error";
		case VT_JSON:
			return "json error";
		case VT_IO:
			return "i/o error";
		case VT_NOMEM:
			return "out of memory";
		case VT_UNIMPL:
			return "unimplemented";
		case VT_UNKNOWN:
			return "unknown error";
		default:
			return "unknown error";
	}
}

const char* vt_error_last(const vt_client* client) {
	(void)client;
	/* TODO: Return the last detailed client error. */
	return NULL;
}
