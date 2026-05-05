/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_IP_ADDRESSES_H
#define VT_IP_ADDRESSES_H 1

#include <stdint.h>
#include <vt/client.h>
#include <vt/error.h>
#include <vt/iter.h>
#include <vt/object.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fetch an IP address object by address.
 *
 * @param client Client used to issue the request.
 * @param ip_address IPv4 or IPv6 address.
 * @param out_ip_address Receives the IP address object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_ip_addresses_get(vt_client* client,
                                            const char* ip_address,
                                            vt_object** out_ip_address);

/**
 * @brief List a relationship collection for an IP address.
 *
 * @param client Client used to issue the request.
 * @param ip_address IPv4 or IPv6 address.
 * @param relationship Relationship name to list.
 * @param limit Maximum number of objects per page, or 0 for API default.
 * @param out_iter Receives an iterator for the relationship collection.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_ip_addresses_relationships(vt_client* client,
                                                      const char* ip_address,
                                                      const char* relationship,
                                                      uint32_t limit,
                                                      vt_iter** out_iter);

// TODO(architect-review): Resource brief requires IP address comments.
/**
 * @brief List comments for an IP address.
 *
 * @param client Client used to issue the request.
 * @param ip_address IPv4 or IPv6 address.
 * @param limit Maximum number of comments per page, or 0 for API default.
 * @param out_iter Receives an iterator for the comments collection.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_ip_addresses_comments(vt_client* client,
                                                 const char* ip_address,
                                                 uint32_t limit,
                                                 vt_iter** out_iter);

// TODO(architect-review): Resource brief requires posting IP address comments.
/**
 * @brief Add a comment to an IP address.
 *
 * @param client Client used to issue the request.
 * @param ip_address IPv4 or IPv6 address.
 * @param text Comment body.
 * @param out_comment Receives the created comment object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_ip_addresses_add_comment(vt_client* client,
                                                    const char* ip_address,
                                                    const char* text,
                                                    vt_object** out_comment);

#ifdef __cplusplus
}
#endif

#endif /* VT_IP_ADDRESSES_H */
