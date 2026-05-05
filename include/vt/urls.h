/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_URLS_H
#define VT_URLS_H 1

#include <stdint.h>
#include <vt/client.h>
#include <vt/error.h>
#include <vt/iter.h>
#include <vt/object.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fetch a URL object by URL id.
 *
 * @param client Client used to issue the request.
 * @param url_id v3 URL id.
 * @param out_url Receives the URL object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_urls_get(vt_client* client, const char* url_id,
                                    vt_object** out_url);

/**
 * @brief Submit a URL for analysis.
 *
 * @param client Client used to issue the request.
 * @param url URL to submit.
 * @param out_analysis Receives the analysis object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_urls_submit(vt_client* client, const char* url,
                                       vt_object** out_analysis);

/**
 * @brief List a relationship collection for a URL.
 *
 * @param client Client used to issue the request.
 * @param url_id v3 URL id.
 * @param relationship Relationship name to list.
 * @param limit Maximum number of objects per page, or 0 for API default.
 * @param out_iter Receives an iterator for the relationship collection.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_urls_relationships(vt_client* client,
                                              const char* url_id,
                                              const char* relationship,
                                              uint32_t limit,
                                              vt_iter** out_iter);

#ifdef __cplusplus
}
#endif

#endif /* VT_URLS_H */
