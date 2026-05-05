/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_FILES_H
#define VT_FILES_H 1

#include <stddef.h>
#include <stdint.h>
#include <vt/client.h>
#include <vt/error.h>
#include <vt/iter.h>
#include <vt/object.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fetch a file object by hash or v3 file id.
 *
 * @param client Client used to issue the request.
 * @param file_id SHA-256, SHA-1, MD5, or v3 file id.
 * @param out_file Receives the file object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_files_get(vt_client* client, const char* file_id,
                                     vt_object** out_file);

/**
 * @brief Submit a file from disk for analysis.
 *
 * @param client Client used to issue the request.
 * @param path Path to the file to submit.
 * @param out_analysis Receives the analysis object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_files_submit_path(vt_client* client,
                                             const char* path,
                                             vt_object** out_analysis);

/**
 * @brief Submit a memory buffer as a file for analysis.
 *
 * @param client Client used to issue the request.
 * @param filename Filename to send with the upload.
 * @param data File contents.
 * @param data_len Length of data in bytes.
 * @param out_analysis Receives the analysis object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_files_submit_buffer(vt_client* client,
                                               const char* filename,
                                               const void* data,
                                               size_t data_len,
                                               vt_object** out_analysis);

// TODO(architect-review): Resource brief requires the upload URL endpoint.
/**
 * @brief Fetch a large-file upload URL.
 *
 * @param client Client used to issue the request.
 * @param out_upload_url Receives the upload URL response object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_files_upload_url(vt_client* client,
                                            vt_object** out_upload_url);

// TODO(architect-review): Resource brief requires file re-analysis.
/**
 * @brief Request re-analysis of a file.
 *
 * @param client Client used to issue the request.
 * @param file_id SHA-256, SHA-1, MD5, or v3 file id.
 * @param out_analysis Receives the analysis object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_files_analyse(vt_client* client, const char* file_id,
                                         vt_object** out_analysis);

/**
 * @brief List a relationship collection for a file.
 *
 * @param client Client used to issue the request.
 * @param file_id SHA-256, SHA-1, MD5, or v3 file id.
 * @param relationship Relationship name to list.
 * @param limit Maximum number of objects per page, or 0 for API default.
 * @param out_iter Receives an iterator for the relationship collection.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_files_relationships(vt_client* client,
                                               const char* file_id,
                                               const char* relationship,
                                               uint32_t limit,
                                               vt_iter** out_iter);

// TODO(architect-review): Resource brief requires file comments.
/**
 * @brief List comments for a file.
 *
 * @param client Client used to issue the request.
 * @param file_id SHA-256, SHA-1, MD5, or v3 file id.
 * @param limit Maximum number of comments per page, or 0 for API default.
 * @param out_iter Receives an iterator for the comments collection.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_files_comments(vt_client* client,
                                          const char* file_id, uint32_t limit,
                                          vt_iter** out_iter);

// TODO(architect-review): Resource brief requires posting file comments.
/**
 * @brief Add a comment to a file.
 *
 * @param client Client used to issue the request.
 * @param file_id SHA-256, SHA-1, MD5, or v3 file id.
 * @param text Comment body.
 * @param out_comment Receives the created comment object.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_files_add_comment(vt_client* client,
                                             const char* file_id,
                                             const char* text,
                                             vt_object** out_comment);

#ifdef __cplusplus
}
#endif

#endif /* VT_FILES_H */
