/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/json.h>

struct vt_json {
	unsigned int reserved;
};

vt_status vt_json_parse(const char* input, size_t input_len,
                        vt_json** out_json) {
	(void)input;
	(void)input_len;
	if (out_json != NULL) {
		*out_json = NULL;
	}
	/* TODO: Parse JSON through the yyjson-backed facade. */
	return VT_UNIMPL;
}

void vt_json_free(vt_json* json) {
	(void)json;
	/* TODO: Release JSON facade state. */
}

const char* vt_json_stringify(const vt_json* json) {
	(void)json;
	/* TODO: Serialize JSON facade state. */
	return NULL;
}
