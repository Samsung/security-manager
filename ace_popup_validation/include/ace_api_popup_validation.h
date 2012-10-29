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
 * @file        ace_popup_validation_api.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This is C api for Access Control Engine (ACE), popup
 *              validation library.
 *
 */

#ifndef ACE_API_H
#define ACE_API_H

#include <ace_api_common.h>

#ifdef __cplusplus
extern "C" {
#endif

// --------------- Initialization and deinitialization -------------------------

/*
 * Initializes the library.
 *
 * Returns error or ACE_OK.
 */
ace_return_t ace_popup_validation_initialize(void);

/*
 * Deinitializes the library.
 *
 * Returns error or ACE_OK.
 */
ace_return_t ace_popup_validation_shutdown(void);

// --------------- Popup answer validation API ---------------------------------

/*
 * Validation of popup answer. This API must be called by implementation of
 * UI handler. The call must be made from safe process, specially labelled by
 * SMACK. If returned value is ACE_OK, 'validation_result' holds validation
 * result that needs to be passed by UI handler as validation result. Otherwise
 * value of 'validation_result' is undefined.
 *
 * See header ace_api_client.h for more details on where this function needs to
 * be called and what arguments need to be passed here.
 *
 * Returns error or ACE_OK.
 */
ace_return_t ace_validate_answer(ace_bool_t answer,
                                 ace_validity_t validity,
                                 const ace_resource_t resource_name,
                                 const ace_session_id_t session_id,
                                 const ace_param_list_t* param_list,
                                 ace_widget_handle_t handle,
                                 ace_bool_t* validation_result);

#ifdef __cplusplus
}
#endif

#endif // ACE_API_H
