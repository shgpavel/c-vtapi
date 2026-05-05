/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/files.h>

vt_status vt_files_get(vt_client* client, const char* file_id,
                       vt_object** out_file) {
	(void)client;
	(void)file_id;
	if (out_file != NULL) {
		*out_file = NULL;
	}
	/* TODO: Fetch /files/{id}. */
	return VT_UNIMPL;
}

vt_status vt_files_submit_path(vt_client* client, const char* path,
                               vt_object** out_analysis) {
	(void)client;
	(void)path;
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	/* TODO: Submit a file path for analysis. */
	return VT_UNIMPL;
}

vt_status vt_files_submit_buffer(vt_client* client, const char* filename,
                                 const void* data, size_t data_len,
                                 vt_object** out_analysis) {
	(void)client;
	(void)filename;
	(void)data;
	(void)data_len;
	if (out_analysis != NULL) {
		*out_analysis = NULL;
	}
	/* TODO: Submit an in-memory file for analysis. */
	return VT_UNIMPL;
}

vt_status vt_files_relationships(vt_client* client, const char* file_id,
                                 const char* relationship, uint32_t limit,
                                 vt_iter** out_iter) {
	(void)client;
	(void)file_id;
	(void)relationship;
	(void)limit;
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	/* TODO: List /files/{id}/{relationship}. */
	return VT_UNIMPL;
}
