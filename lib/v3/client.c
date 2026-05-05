/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/client.h>

struct vt_client {
	unsigned int reserved;
};

vt_client* vt_client_new(const char* api_key) {
	(void)api_key;
	/* TODO: Allocate and initialize the v3 client. */
	return NULL;
}

void vt_client_free(vt_client* client) {
	(void)client;
	/* TODO: Release client state. */
}

vt_status vt_client_set_base_url(vt_client* client, const char* base_url) {
	(void)client;
	(void)base_url;
	/* TODO: Store the v3 API base URL override. */
	return VT_UNIMPL;
}

vt_status vt_client_set_user_agent(vt_client* client, const char* user_agent) {
	(void)client;
	(void)user_agent;
	/* TODO: Store the v3 client User-Agent value. */
	return VT_UNIMPL;
}

vt_status vt_client_set_timeout_ms(vt_client* client, uint64_t timeout_ms) {
	(void)client;
	(void)timeout_ms;
	/* TODO: Store request timeout configuration. */
	return VT_UNIMPL;
}

vt_status vt_client_set_transport(vt_client* client, vt_http_send_fn send,
                                  void* userdata) {
	(void)client;
	(void)send;
	(void)userdata;
	/* TODO: Store the HTTP transport hook. */
	return VT_UNIMPL;
}
