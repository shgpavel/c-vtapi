/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_INTELLIGENCE_H
#define VT_INTELLIGENCE_H 1

#include <stdbool.h>
#include <stdint.h>
#include <vt/client.h>
#include <vt/error.h>
#include <vt/iter.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Search VirusTotal Intelligence.
 *
 * @param client Client used to issue the request.
 * @param query Intelligence search query.
 * @param limit Maximum number of objects per page.
 * @param descriptors_only Whether to return only object descriptors.
 * @param out_iter Receives an iterator over matching file, URL, domain, or IP
 * address objects.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_intelligence_search(vt_client* client,
                                               const char* query,
                                               uint32_t limit,
                                               bool descriptors_only,
                                               vt_iter** out_iter);

#ifdef __cplusplus
}
#endif

#endif /* VT_INTELLIGENCE_H */
