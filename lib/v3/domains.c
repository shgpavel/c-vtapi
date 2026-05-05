/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/domains.h>

vt_status vt_domains_get(vt_client* client, const char* domain,
                         vt_object** out_domain) {
	(void)client;
	(void)domain;
	if (out_domain != NULL) {
		*out_domain = NULL;
	}
	/* TODO: Fetch /domains/{domain}. */
	return VT_UNIMPL;
}

vt_status vt_domains_relationships(vt_client* client, const char* domain,
                                   const char* relationship, uint32_t limit,
                                   vt_iter** out_iter) {
	(void)client;
	(void)domain;
	(void)relationship;
	(void)limit;
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	/* TODO: List /domains/{domain}/{relationship}. */
	return VT_UNIMPL;
}
