/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        ace_api_client.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This is C api for Access Control Engine (ACE), client mode
 *              (RO part).
 */

#ifndef ACE_API_CLIENT_H
#define ACE_API_CLIENT_H

#include <ace_api_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * API defined in this header should be used only from one thread. If used
 * otherwise, unexpected behaviour may occur, including segmentation faults and
 * escalation of global warming. Be warned.
 */

// --------------- Initialization and deinitialization -------------------------

/*
 * Function type that must be implemented externally and passed to ACE
 * on initialization. This function must show to the user a popup with
 * information on access request to single device capability. Will be used by
 * implementation of ace_check_access API, when policy requires to display
 * popup.
 *
 * Function must be synchronous and must behave accordingly:
 *
 * Function may return value other than ACE_OK, but it will be treated as
 * denial of access.
 *
 * If returned value is ACE_OK, then 'validation_result' must hold information
 * on whether the access was granted or not.
 *
 * Executed function must display a popup with readable information presented to
 * user, covering 'resource_name' that is to be accessed for 'handle' widget
 * which is requesting the access.
 *
 * In its implementation, after the user answered to displayed question,
 * UI handler must call popup answer validation API (ace_validate_answer)
 * from separate, ace-popup-validation library, with passed 'param_list',
 * 'session_id', 'handle' and given answer as arguments. Validation result
 * returned by ace_validate_answer needs to be returned in 'validation_result'
 * parameter of UI handler.
 *
 * 'popup_type' describes what kind of options should be given to user - i.e.
 * ONESHOT prompt only gives possibility to answer Permit/Deny and returned
 * validity for this prompt must be ONCE. PER_SESSION prompt allows to return
 * validity ONCE or PER_SESSION. BLANKET prompt allows to return any validity,
 * as defined in ace_validity_t.
 *
 * This call must be made from properly SMACK labelled, safe process - otherwise
 * the validation will not occur in security daemon and caller will not be
 * granted access to requested device capability.
 */
typedef ace_return_t (*ace_popup_handler_func_t)(
        ace_popup_t popup_type,
        const ace_resource_t resource_name,
        const ace_session_id_t session_id,
        const ace_param_list_t* param_list,
        ace_widget_handle_t handle,
        ace_bool_t* validation_result);

/*
 * Initializes ACE for check access API (client mode). Must be called only once.
 * Keep in mind that initializing ACE in client mode disallows usage of API
 * defined in ace_api.h and ace_api_settings.h (RW part).
 *
 * 'handler' must not be NULL, see definition of ace_popup_handler_func_t for
 * more information.
 *
 * Returns error or ACE_OK.
 */
ace_return_t ace_client_initialize(ace_popup_handler_func_t handler);

/*
 * Deinitializes ACE client for check access API. Can be called only once.
 */
ace_return_t ace_client_shutdown(void);

// --------------- Check Access API --------------------------------------------

/*
 * Does ACE check with set of device capabilities and function parameters.
 * Checks cache first, if it is non-existent, does full ACE check.
 *
 * Returns error or ACE_OK and information if access was allowed or not
 * (value ACE_TRUE or ACE_FALSE is in 'access' argument, only if returned value
 * is ACE_OK - otherwise, 'access' value is undefined)
 */
ace_return_t ace_check_access(const ace_request_t* request, ace_bool_t* access);

#ifdef __cplusplus
}
#endif

#endif // ACE_API_CLIENT_H
