/*
 *    Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        wrt_oscp_api.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This is C api for WRT OCSP
 */
#ifndef WRT_OCSP_API_H
#define WRT_OCSP_API_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum{
  WRT_OCSP_OK,
  WRT_OCSP_INVALID_ARGUMENTS,
  WRT_OCSP_INTERNAL_ERROR
}wrt_ocsp_return_t;

typedef int wrt_ocsp_widget_handle_t;
typedef enum {
  //The certificate has not been revoked.
  WRT_OCSP_WIDGET_VERIFICATION_STATUS_GOOD,

  //The certificate has been revoked.
  WRT_OCSP_WIDGET_VERIFICATION_STATUS_REVOKED


}wrt_ocsp_widget_verification_status_t;

//-------------Initialization and shutdown-------------------
/*
 * Establishes connection to security server. Must be called only once.
 * Returns WRT_OCSP_OK or error
 */
wrt_ocsp_return_t wrt_ocsp_initialize(void);

/*
 * Deinitializes internal structures. Must be called only once.
 * Returns WRT_OCSP_OK or error
 */

wrt_ocsp_return_t wrt_ocsp_shutdown(void);

//-------------Widget verification------------------------------
/*
 * Requests verification for widget identified with 'handle'.
 * 'status holds server response.
 * Returns WRT_OCSP_OK or error
 */

wrt_ocsp_return_t wrt_ocsp_verify_widget(wrt_ocsp_widget_handle_t handle,
                                         wrt_ocsp_widget_verification_status_t* status);


#ifdef __cplusplus
}
#endif
#endif //WRT_OCSP_API_H
