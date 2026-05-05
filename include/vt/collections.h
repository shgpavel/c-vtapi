/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_COLLECTIONS_H
#define VT_COLLECTIONS_H 1

#include <stdint.h>
#include <vt/client.h>
#include <vt/error.h>
#include <vt/iter.h>
#include <vt/object.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fetch a collection object by id.
 *
 * @param client Client used to issue the request.
 * @param id Collection id.
 * @param out_collection Receives the collection object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_collections_get(vt_client* client, const char* id,
                                           vt_object** out_collection);

/**
 * @brief List a relationship collection for a collection.
 *
 * @param client Client used to issue the request.
 * @param id Collection id.
 * @param relationship Relationship name, such as files, urls, domains, or
 * ip_addresses.
 * @param limit Maximum number of objects per page, or 0 for API default.
 * @param out_iter Receives an iterator for the relationship collection.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_collections_relationships(vt_client* client,
                                                     const char* id,
                                                     const char* relationship,
                                                     uint32_t limit,
                                                     vt_iter** out_iter);

#ifdef __cplusplus
}
#endif

#endif /* VT_COLLECTIONS_H */
