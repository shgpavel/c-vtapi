/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/analyses.h>

vt_status vt_analyses_get(vt_client* client, const char* analysis_id,
                          vt_object** out_analysis) {
	(void)client;
	(void)analysis_id;
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	/* TODO: Fetch /analyses/{id}. */
	return VT_UNIMPL;
}

vt_status vt_analyses_relationships(vt_client* client, const char* analysis_id,
                                    const char* relationship, uint32_t limit,
                                    vt_iter** out_iter) {
	(void)client;
	(void)analysis_id;
	(void)relationship;
	(void)limit;
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	/* TODO: List /analyses/{id}/{relationship}. */
	return VT_UNIMPL;
}
