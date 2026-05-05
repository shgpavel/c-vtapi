/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_ANALYSES_H
#define VT_ANALYSES_H 1

#include <stdint.h>
#include <vt/client.h>
#include <vt/error.h>
#include <vt/iter.h>
#include <vt/object.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fetch an analysis object by analysis id.
 *
 * @param client Client used to issue the request.
 * @param analysis_id v3 analysis id.
 * @param out_analysis Receives the analysis object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_analyses_get(vt_client* client,
                                        const char* analysis_id,
                                        vt_object** out_analysis);

/**
 * @brief List a relationship collection for an analysis.
 *
 * @param client Client used to issue the request.
 * @param analysis_id v3 analysis id.
 * @param relationship Relationship name to list.
 * @param limit Maximum number of objects per page, or 0 for API default.
 * @param out_iter Receives an iterator for the relationship collection.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_analyses_relationships(vt_client* client,
                                                  const char* analysis_id,
                                                  const char* relationship,
                                                  uint32_t limit,
                                                  vt_iter** out_iter);

#ifdef __cplusplus
}
#endif

#endif /* VT_ANALYSES_H */
