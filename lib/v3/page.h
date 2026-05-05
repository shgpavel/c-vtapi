/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_V3_PAGE_H
#define VT_V3_PAGE_H 1

#include <stddef.h>
#include <stdlib.h>

#include "http.h"

vt_status vt_page_send_object(vt_client* client, vt_http_method method,
                              const char* path, const void* body,
                              size_t body_len, const char* content_type,
                              const vt_http_multipart_part* multipart,
                              size_t multipart_len, vt_object** out_object);
vt_status vt_page_send_path_object(vt_client* client, vt_http_method method,
                                   char* path, const void* body,
                                   size_t body_len, const char* content_type,
                                   vt_object** out_object);
vt_status vt_page_send_path_multipart(vt_client* client, vt_http_method method,
                                      char* path,
                                      const vt_http_multipart_part* multipart,
                                      size_t multipart_len,
                                      vt_object** out_object);
vt_status vt_page_send_path_comment(vt_client* client, char* path,
                                    const char* text, vt_object** out_object);
vt_status vt_page_parse_objects(const vt_http_response* response,
                                vt_object*** out_objects, size_t* out_count,
                                char** out_next_url, char** out_cursor,
                                void* userdata);

#ifndef VT_PAGE_NO_INLINE_ITER
static inline vt_status vt_page_iter_from_path(vt_client* client, char* path,
                                               vt_iter** out_iter) {
	if (out_iter != NULL) {
		*out_iter = NULL;
	}
	if (path == NULL) {
		return vt_client_set_error(client, VT_NOMEM,
		                           "failed to allocate request path");
	}

	const vt_status status =
	    vt_iter_new(client, path, vt_page_parse_objects, client, out_iter);
	free(path);
	return status;
}
#endif

#endif /* VT_V3_PAGE_H */
