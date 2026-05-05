/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/urls.h>

vt_status vt_urls_get(vt_client* client, const char* url_id,
                      vt_object** out_url) {
	(void)client;
	(void)url_id;
	if (out_url != NULL) {
		*out_url = NULL;
	}
	/* TODO: Fetch /urls/{id}. */
	return VT_UNIMPL;
}

vt_status vt_urls_submit(vt_client* client, const char* url,
                         vt_object** out_analysis) {
	(void)client;
	(void)url;
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	/* TODO: Submit a URL for analysis. */
	return VT_UNIMPL;
}

vt_status vt_urls_relationships(vt_client* client, const char* url_id,
                                const char* relationship, uint32_t limit,
                                vt_iter** out_iter) {
	(void)client;
	(void)url_id;
	(void)relationship;
	(void)limit;
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	/* TODO: List /urls/{id}/{relationship}. */
	return VT_UNIMPL;
}
