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
 * @file        ace_api_setup.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This is C api for Access Control Engine (ACE), installer mode
 *              (RW part).
 *
 */

#ifndef ACE_API_H
#define ACE_API_H

#include <ace_api_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * API defined in this header should be used only from one thread. If used
 * otherwise, unexpected behaviour may occur, including segmentation faults and
 * escalation of global warming. Be warned.
 */

// --------------- Initialization and policy update ----------------------------

/*
 * Initializes ACE - connects (RW) to the database. Must be called only once.
 * Returns ACE_OK or error
 */
ace_return_t ace_install_initialize(void);

/*
 * Deinitializes ACE - deinitialize internal structures, detach DB, etc.
 * Must be called only once.
 * Returns ACE_OK or error
 */
ace_return_t ace_install_shutdown(void);

/*
 * Updates policy - parses XML files from known locations (reason for no arguments),
 * also clears policy and prompt caches.
 * Returns ACE_OK or error
 */
ace_return_t ace_update_policy(void);

// --------------- Requested device capabilities API for installer -------------

typedef struct
{
    ace_string_t   device_capability;
    ace_bool_t     smack_granted;
} ace_requested_dev_cap_t;

typedef struct
{
    ace_size_t              count;
    ace_requested_dev_cap_t*  items;
} ace_requested_dev_cap_list_t;

/*
 * Deletes data allocated by ace_get_requested_dev_caps - a helper function
 */
ace_return_t ace_free_requested_dev_caps(ace_requested_dev_cap_list_t* caps);

/*
 * Returns ACE_OK or error; 'caps' will hold device capabilities information.
 * To free allcated resources in 'caps', use ace_free_requested_dev_caps
 */
ace_return_t ace_get_requested_dev_caps(ace_widget_handle_t handle,
                                        ace_requested_dev_cap_list_t* caps);

/*
 * Returns error or ACE_OK
 */
ace_return_t ace_set_requested_dev_caps(ace_widget_handle_t handle,
                                        const ace_requested_dev_cap_list_t* caps);

// ---------------- Accepted Api featuresk API for installer ----------------


ace_return_t ace_set_accepted_feature(ace_widget_handle_t handle,
                                      const ace_feature_list_t* flist);

ace_return_t ace_rem_accepted_feature(ace_widget_handle_t handle);

// --------------- Widget data setup for installation --------------------------

typedef enum
{
    WAC20 = 0,
    Tizen
} ace_widget_type_t;

struct widget_info {
    ace_widget_type_t type;
    ace_string_t id;
    ace_string_t version;
    ace_string_t author;
    ace_string_t shareHerf;
};

typedef enum
{
    AUTHOR,
    DISTRIBUTOR,
    UNKNOWN
} ace_cert_owner_t;

typedef enum
{
    ROOT,
    ENDENTITY
} ace_cert_type_t;

typedef struct certificate_data {
    ace_cert_owner_t owner;
    ace_cert_type_t type;
    int chain_id;
    ace_string_t md5_fp;
    ace_string_t sha1_fp;
    ace_string_t common_name;
} ace_certificate_data;

/*
 * Register widget info into database.
 * @param cert_data NULL terminated list of widget certificates
 */

ace_return_t ace_register_widget(ace_widget_handle_t handle,
                                 struct widget_info* info,
                                 ace_certificate_data* cert_data[]);

ace_return_t ace_unregister_widget(ace_widget_handle_t handle);

ace_return_t ace_is_widget_installed(ace_widget_handle_t handle, bool *installed);

/*
 * Gets widget type in 'type'. Use in installer to determine which policy will be used
 * by ACE for this widget.
 * Returns error or ACE_OK
 */
ace_return_t ace_get_widget_type(ace_widget_handle_t handle,
                                 ace_widget_type_t* type);

// --------------- Installation time policy check ------------------------------

typedef enum
{
    ACE_PERMIT,
    ACE_DENY,
    ACE_PROMPT,
    ACE_UNDEFINED
} ace_policy_result_t;

/*
 * Gets current policy evaluation for given device capability and given widget.
 * Returns error or ACE_OK
 */
ace_return_t ace_get_policy_result(const ace_resource_t,
                                   ace_widget_handle_t handle,
                                   ace_policy_result_t* result);

#ifdef __cplusplus
}
#endif

#endif // ACE_API_H
