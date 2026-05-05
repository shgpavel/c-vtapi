/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_FEEDS_H
#define VT_FEEDS_H 1

#include <stddef.h>
#include <vt/client.h>
#include <vt/error.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fetch the file feed bundle for a time slice.
 *
 * @param client Client used to issue the request.
 * @param time_param Feed time in YYYYMMDDHHmm format.
 * @param out_buf Receives the raw bzip2-compressed response bytes. Free with
 * free().
 * @param out_len Receives the number of bytes in out_buf.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_feeds_files(vt_client* client,
                                       const char* time_param, void** out_buf,
                                       size_t* out_len);

/**
 * @brief Fetch the URL feed bundle for a time slice.
 *
 * @param client Client used to issue the request.
 * @param time_param Feed time in YYYYMMDDHHmm format.
 * @param out_buf Receives the raw bzip2-compressed response bytes. Free with
 * free().
 * @param out_len Receives the number of bytes in out_buf.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_feeds_urls(vt_client* client, const char* time_param,
                                      void** out_buf, size_t* out_len);

/**
 * @brief Fetch one file feed item from a time slice.
 *
 * @param client Client used to issue the request.
 * @param time_param Feed time in YYYYMMDDHHmm format.
 * @param sha256 SHA-256 hash of the file feed item.
 * @param out_buf Receives the raw bzip2-compressed response bytes. Free with
 * free().
 * @param out_len Receives the number of bytes in out_buf.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_feeds_file_for(vt_client* client,
                                          const char* time_param,
                                          const char* sha256, void** out_buf,
                                          size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* VT_FEEDS_H */
