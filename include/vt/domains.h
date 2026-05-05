/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_DOMAINS_H
#define VT_DOMAINS_H 1

#include <stdint.h>
#include <vt/client.h>
#include <vt/error.h>
#include <vt/iter.h>
#include <vt/object.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fetch a domain object by domain name.
 *
 * @param client Client used to issue the request.
 * @param domain Domain name.
 * @param out_domain Receives the domain object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_domains_get(vt_client* client, const char* domain,
                                       vt_object** out_domain);

/**
 * @brief List a relationship collection for a domain.
 *
 * @param client Client used to issue the request.
 * @param domain Domain name.
 * @param relationship Relationship name to list.
 * @param limit Maximum number of objects per page, or 0 for API default.
 * @param out_iter Receives an iterator for the relationship collection.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_domains_relationships(vt_client* client,
                                                 const char* domain,
                                                 const char* relationship,
                                                 uint32_t limit,
                                                 vt_iter** out_iter);

#ifdef __cplusplus
}
#endif

#endif /* VT_DOMAINS_H */
