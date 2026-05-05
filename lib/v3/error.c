/* SPDX-License-Identifier: Apache-2.0 */

#include "http.h"

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
	return client == NULL ? NULL : client->last_error;
}

vt_status vt_http_status_to_vt_status(long status_code) {
	if (status_code >= 200 && status_code < 400) {
		return VT_OK;
	}
	if (status_code == 0) {
		return VT_NETWORK;
	}
	if (status_code == 401 || status_code == 403) {
		return VT_AUTH;
	}
	if (status_code == 404) {
		return VT_NOT_FOUND;
	}
	if (status_code == 429) {
		return VT_RATE_LIMIT;
	}
	if (status_code >= 500 && status_code <= 599) {
		return VT_SERVER;
	}

	return VT_UNKNOWN;
}
