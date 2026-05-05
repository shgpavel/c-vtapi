/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/iter.h>

struct vt_iter {
	unsigned int reserved;
};

vt_status vt_iter_next(vt_iter* iter, vt_object** out_object) {
	(void)iter;
	if (out_object != NULL) {
		*out_object = NULL;
	}
	/* TODO: Fetch or return the next object in the cursor page. */
	return VT_UNIMPL;
}

void vt_iter_free(vt_iter* iter) {
	(void)iter;
	/* TODO: Release iterator and pagination state. */
}

vt_status vt_iter_error(const vt_iter* iter) {
	(void)iter;
	/* TODO: Return the iterator's last error. */
	return VT_UNIMPL;
}

const char* vt_iter_cursor(const vt_iter* iter) {
	(void)iter;
	/* TODO: Return the current pagination cursor. */
	return NULL;
}
