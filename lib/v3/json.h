/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_V3_JSON_H
#define VT_V3_JSON_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <vt/error.h>
#include <vt/iter.h>
#include <vt/json.h>
#include <vt/object.h>
#include <yyjson.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vt_json_doc vt_json_doc;

typedef vt_status (*vt_json_page_fetch_fn)(const char* cursor,
                                           const char* next_url, void* userdata,
                                           vt_json** out_json);

typedef struct vt_json_page_fetcher {
	vt_json_page_fetch_fn fetch;
	void* userdata;
} vt_json_page_fetcher;

struct vt_json {
	vt_json_doc* doc;
	char* stringified;
};

struct vt_object {
	vt_json_doc* doc;
	yyjson_val* value;
	char* scratch;
};

struct vt_iter {
	vt_json_doc* doc;
	yyjson_val* data;
	size_t index;
	size_t count;
	const char* cursor;
	const char* next_url;
	vt_status last_error;
	vt_json_page_fetcher fetcher;
};

/**
 * @brief Parse JSON into a yyjson-backed facade.
 *
 * @param buf JSON input bytes.
 * @param len JSON input length.
 * @param out Receives VT_OK or the parse/API error status.
 * @return Parsed document, or NULL on error.
 */
[[nodiscard]] vt_json* vt_json_parse_buffer(const void* buf, size_t len,
                                            vt_status* out);

#ifndef VT_JSON_INTERNAL_NO_PARSE_ALIAS
#define vt_json_parse(buf, len, out) vt_json_parse_buffer((buf), (len), (out))
#endif

/**
 * @brief Free a JSON facade.
 *
 * @param json JSON facade to free, or NULL.
 */
void vt_json_free(vt_json* json);

/**
 * @brief Return a compact JSON string for a document facade.
 *
 * @param json JSON document to inspect.
 * @return String owned by json, or NULL.
 */
[[nodiscard]] const char* vt_json_stringify(const vt_json* json);

/**
 * @brief Extract the single-object data envelope.
 *
 * @param json Parsed v3 envelope.
 * @return Object backed by the parsed document, or NULL.
 */
[[nodiscard]] vt_object* vt_json_to_object(vt_json* json);

/**
 * @brief Extract an array page from a collection envelope.
 *
 * @param json Parsed v3 collection envelope.
 * @param fetcher Optional next-page fetch callback.
 * @param out Receives VT_OK or the envelope/API error status.
 * @return Iterator page backed by the parsed document, or NULL.
 */
[[nodiscard]] vt_iter* vt_json_to_page(vt_json* json,
                                       const vt_json_page_fetcher* fetcher,
                                       vt_status* out);

/**
 * @brief Return mapped API error status for a parsed envelope.
 *
 * @param json Parsed v3 envelope.
 * @return VT_OK when the envelope has no error object.
 */
[[nodiscard]] vt_status vt_json_error_status(const vt_json* json);

/**
 * @brief Return the API error code string from an error envelope.
 *
 * @param json Parsed v3 envelope.
 * @return Error code owned by json, or NULL.
 */
[[nodiscard]] const char* vt_json_error_code(const vt_json* json);

/**
 * @brief Return the API error message string from an error envelope.
 *
 * @param json Parsed v3 envelope.
 * @return Error message owned by json, or NULL.
 */
[[nodiscard]] const char* vt_json_error_message(const vt_json* json);

/**
 * @brief Build a v3 comment POST JSON body.
 *
 * @param text Comment body text.
 * @param out_len Receives serialized buffer length.
 * @param out Receives VT_OK or an error status.
 * @return Serialized JSON buffer, or NULL on error.
 */
[[nodiscard]] char* vt_json_build_comment(const char* text, size_t* out_len,
                                          vt_status* out);

/**
 * @brief Free a buffer returned by a v3 JSON builder.
 *
 * @param buffer Buffer to free, or NULL.
 */
void vt_json_buffer_free(char* buffer);

[[nodiscard]] vt_json_doc* vt_json_doc_ref(vt_json_doc* doc);
void vt_json_doc_unref(vt_json_doc* doc);
[[nodiscard]] yyjson_val* vt_json_doc_root(const vt_json_doc* doc);

[[nodiscard]] vt_object* vt_object_from_value(vt_json_doc* doc,
                                              yyjson_val* value);
[[nodiscard]] const char* vt_object_attributes_get_str(const vt_object* object,
                                                       const char* name);
[[nodiscard]] bool vt_object_attributes_get_int(const vt_object* object,
                                                const char* name, int64_t* out);
[[nodiscard]] bool vt_object_attributes_get_bool(const vt_object* object,
                                                 const char* name, bool* out);
[[nodiscard]] bool vt_object_attributes_get_double(const vt_object* object,
                                                   const char* name,
                                                   double* out);
[[nodiscard]] vt_object* vt_object_relationships_get(const vt_object* object,
                                                     const char* name);
[[nodiscard]] const char* vt_object_links_get_str(const vt_object* object,
                                                  const char* name);

#ifdef __cplusplus
}
#endif

#endif /* VT_V3_JSON_H */
