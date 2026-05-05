/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_ITER_H
#define VT_ITER_H 1

#include <vt/error.h>
#include <vt/object.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vt_iter vt_iter;

/**
 * @brief Advance a cursor-backed collection iterator.
 *
 * @param iter Iterator to advance.
 * @param out_object Receives the next object when available.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_iter_next(vt_iter* iter, vt_object** out_object);

/**
 * @brief Free a cursor-backed collection iterator.
 *
 * @param iter Iterator to free, or NULL.
 * @return Nothing.
 */
void vt_iter_free(vt_iter* iter);

/**
 * @brief Return the most recent iterator error.
 *
 * @param iter Iterator to inspect.
 * @return Last iterator status.
 */
[[nodiscard]] vt_status vt_iter_error(const vt_iter* iter);

/**
 * @brief Return the current pagination cursor.
 *
 * @param iter Iterator to inspect.
 * @return Cursor owned by the iterator, or NULL when unavailable.
 */
[[nodiscard]] const char* vt_iter_cursor(const vt_iter* iter);

#ifdef __cplusplus
}
#endif

#endif /* VT_ITER_H */
