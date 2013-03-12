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
 * @file        ace_api_settings.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This is header for ACE settings API (RW part).
 */

#ifndef ACE_API_SETTINGS_H
#define ACE_API_SETTINGS_H

#include <ace_api_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * API defined in this header should be used only from one thread. If used
 * otherwise, unexpected behaviour may occur, including segmentation faults and
 * escalation of global warming. Be warned.
 */

// --------------- Initialization ----------------------------------------------

/*
 * Initializes ACE - connects (RW) to the database. Must be called only once.
 * Returns ACE_OK or error
 */
ace_return_t ace_settings_initialize(void);

/*
 * Deinitializes ACE - deinitialize internal structures, detach DB, etc.
 * Must be called only once.
 * Returns ACE_OK or error
 */
ace_return_t ace_settings_shutdown(void);

// --------------- Resource settings API ---------------------------------------

/*
 * Order and values of enum constants are part of API
 */
typedef enum
{
    ACE_PREFERENCE_PERMIT,
    ACE_PREFERENCE_DENY,
    ACE_PREFERENCE_DEFAULT,         // means: not set
    ACE_PREFERENCE_BLANKET_PROMPT,
    ACE_PREFERENCE_SESSION_PROMPT,
    ACE_PREFERENCE_ONE_SHOT_PROMPT
} ace_preference_t;

/*
 * Returns error or ACE_OK
 * If return value is ACE_OK, 'prerefence' value is the queried one, otherwise
 * 'preference' value is undefined
 */
ace_return_t ace_get_widget_resource_preference(ace_widget_handle_t handle,
                                                const ace_resource_t resource,
                                                ace_preference_t* preference);

/*
 * Returns error or ACE_OK
 * If return value is ACE_OK, 'prerefence' value is the queried one, otherwise
 * 'preference' value is undefined
 */
ace_return_t ace_get_global_resource_preference(const ace_resource_t resource,
        ace_preference_t* preference);

/*
 * To reset setting, pass ACE_PREFERENCE_DEFAULT
 * Returns error or ACE_OK
 */
ace_return_t ace_set_widget_resource_preference(ace_widget_handle_t handle,
                                                const ace_resource_t resource,
                                                ace_preference_t preference);

/*
 * To reset setting, pass ACE_PREFERENCE_DEFAULT
 * Returns error or ACE_OK
 */
ace_return_t ace_set_global_resource_preference(const ace_resource_t resource,
                                                ace_preference_t preference);

/*
 * Resets per widget resource settings to ACE_PREFERENCE_DEFAULT
 */
ace_return_t ace_reset_widget_resource_settings(void);

/*
 * Resets global resource settings to ACE_PREFERENCE_DEFAULT
 */
ace_return_t ace_reset_global_resource_settings(void);

/*
 * After execution, is_privacy_api is ACE_TRUE if resource_name is the name
 * of Privacy API
 */
ace_return_t ace_is_private_api(const ace_resource_t resource_name,
                       ace_bool_t* is_private_api);

#ifdef __cplusplus
}
#endif

#endif // ACE_API_SETTINGS_H
