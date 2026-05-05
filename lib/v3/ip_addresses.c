/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/ip_addresses.h>

vt_status vt_ip_addresses_get(vt_client* client, const char* ip_address,
                              vt_object** out_ip_address) {
	(void)client;
	(void)ip_address;
	if (out_ip_address != NULL) {
		*out_ip_address = NULL;
	}
	/* TODO: Fetch /ip_addresses/{ip}. */
	return VT_UNIMPL;
}

vt_status vt_ip_addresses_relationships(vt_client* client,
                                        const char* ip_address,
                                        const char* relationship,
                                        uint32_t limit, vt_iter** out_iter) {
	(void)client;
	(void)ip_address;
	(void)relationship;
	(void)limit;
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	/* TODO: List /ip_addresses/{ip}/{relationship}. */
	return VT_UNIMPL;
}
