/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_JSON_H
#define VT_JSON_H 1

#include <stddef.h>
#include <vt/error.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vt_json vt_json;

/**
 * @brief Parse a JSON document into the opaque v3 JSON facade.
 *
 * @param input UTF-8 JSON input.
 * @param input_len Length of input in bytes.
 * @param out_json Receives the parsed JSON document.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_json_parse(const char* input, size_t input_len,
                                      vt_json** out_json);

/**
 * @brief Free a JSON document facade.
 *
 * @param json JSON document to free, or NULL.
 * @return Nothing.
 */
void vt_json_free(vt_json* json);

/**
 * @brief Return a compact JSON string for a document facade.
 *
 * @param json JSON document to inspect.
 * @return JSON string owned by the document, or NULL when unavailable.
 */
[[nodiscard]] const char* vt_json_stringify(const vt_json* json);

#ifdef __cplusplus
}
#endif

#endif /* VT_JSON_H */
