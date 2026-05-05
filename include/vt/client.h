/* SPDX-License-Identifier: Apache-2.0 */

#ifndef VT_CLIENT_H
#define VT_CLIENT_H 1

#include <stdint.h>
#include <vt/error.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vt_client vt_client;
typedef struct vt_http_request vt_http_request;
typedef struct vt_http_response vt_http_response;

/**
 * @brief HTTP transport callback used by the v3 client.
 *
 * @param client Client issuing the request.
 * @param request Request prepared by the library.
 * @param response Response storage filled by the transport.
 * @param userdata Caller-provided transport data.
 * @return VT_OK on success, or a vt_status error code.
 */
typedef vt_status (*vt_http_send_fn)(vt_client* client,
                                     const vt_http_request* request,
                                     vt_http_response* response,
                                     void* userdata);

/**
 * @brief Create a VirusTotal API v3 client.
 *
 * @param api_key API key used for the x-apikey request header.
 * @return New client, or NULL on allocation or validation failure.
 */
[[nodiscard]] vt_client* vt_client_new(const char* api_key);

/**
 * @brief Free a VirusTotal API v3 client.
 *
 * @param client Client to free, or NULL.
 * @return Nothing.
 */
void vt_client_free(vt_client* client);

/**
 * @brief Override the API base URL.
 *
 * @param client Client to configure.
 * @param base_url Base URL such as https://www.virustotal.com/api/v3.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_client_set_base_url(vt_client* client,
                                               const char* base_url);

/**
 * @brief Override the User-Agent header.
 *
 * @param client Client to configure.
 * @param user_agent User-Agent header value.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_client_set_user_agent(vt_client* client,
                                                 const char* user_agent);

/**
 * @brief Set the request timeout.
 *
 * @param client Client to configure.
 * @param timeout_ms Request timeout in milliseconds.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_client_set_timeout_ms(vt_client* client,
                                                 uint64_t timeout_ms);

/**
 * @brief Install a custom HTTP transport.
 *
 * @param client Client to configure.
 * @param send Transport callback, or NULL to restore the default transport.
 * @param userdata Caller data passed to the transport callback.
 * @return VT_OK on success, or a vt_status error code.
 */
[[nodiscard]] vt_status vt_client_set_transport(vt_client* client,
                                                vt_http_send_fn send,
                                                void* userdata);

#ifdef __cplusplus
}
#endif

#endif /* VT_CLIENT_H */
