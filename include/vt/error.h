/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_ERROR_H
#define VT_ERROR_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vt_client vt_client;

/**
 * @brief Status codes returned by fallible VirusTotal API v3 functions.
 */
typedef enum vt_status {
	VT_OK = 0,
	VT_INVALID_ARG,
	VT_AUTH,
	VT_NOT_FOUND,
	VT_RATE_LIMIT,
	VT_SERVER,
	VT_NETWORK,
	VT_JSON,
	VT_IO,
	VT_NOMEM,
	VT_UNIMPL,
	VT_UNKNOWN,
} vt_status;

/**
 * @brief Return a stable string for a status code.
 *
 * @param status Status code to describe.
 * @return Constant string describing the status code.
 */
[[nodiscard]] const char* vt_status_str(vt_status status);

/**
 * @brief Return the most recent detailed client error message.
 *
 * @param client Client whose last error should be inspected.
 * @return Error message owned by the client, or NULL when unavailable.
 */
[[nodiscard]] const char* vt_error_last(const vt_client* client);

#ifdef __cplusplus
}
#endif

#endif /* VT_ERROR_H */
