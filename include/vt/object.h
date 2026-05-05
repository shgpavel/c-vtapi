/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_OBJECT_H
#define VT_OBJECT_H 1

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vt_object vt_object;

/**
 * @brief Free an object returned by the v3 client.
 *
 * @param object Object to free, or NULL.
 * @return Nothing.
 */
void vt_object_free(vt_object* object);

/**
 * @brief Return the v3 envelope item id.
 *
 * @param object Object to inspect.
 * @return Object id owned by the object, or NULL when unavailable.
 */
[[nodiscard]] const char* vt_object_id(const vt_object* object);

/**
 * @brief Return the v3 envelope item type.
 *
 * @param object Object to inspect.
 * @return Object type owned by the object, or NULL when unavailable.
 */
[[nodiscard]] const char* vt_object_type(const vt_object* object);

/**
 * @brief Return a raw attribute value by name.
 *
 * @param object Object to inspect.
 * @param name Attribute name.
 * @return Attribute value owned by the object, or NULL when unavailable.
 */
[[nodiscard]] const char* vt_object_attribute(const vt_object* object,
                                              const char* name);

/**
 * @brief Return a raw relationship value by name.
 *
 * @param object Object to inspect.
 * @param name Relationship name.
 * @return Relationship value owned by the object, or NULL when unavailable.
 */
[[nodiscard]] const char* vt_object_relationship(const vt_object* object,
                                                 const char* name);

/**
 * @brief Return a link value by name.
 *
 * @param object Object to inspect.
 * @param name Link name.
 * @return Link value owned by the object, or NULL when unavailable.
 */
[[nodiscard]] const char* vt_object_link(const vt_object* object,
                                         const char* name);

/**
 * @brief Return the number of attributes on an object.
 *
 * @param object Object to inspect.
 * @return Attribute count, or 0 when unavailable.
 */
[[nodiscard]] size_t vt_object_attribute_count(const vt_object* object);

/**
 * @brief Return the number of relationships on an object.
 *
 * @param object Object to inspect.
 * @return Relationship count, or 0 when unavailable.
 */
[[nodiscard]] size_t vt_object_relationship_count(const vt_object* object);

/**
 * @brief Return the number of links on an object.
 *
 * @param object Object to inspect.
 * @return Link count, or 0 when unavailable.
 */
[[nodiscard]] size_t vt_object_link_count(const vt_object* object);

#ifdef __cplusplus
}
#endif

#endif /* VT_OBJECT_H */
