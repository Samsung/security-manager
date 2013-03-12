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
 * @file        ace_api_common.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This is header for basic ACE data types and error codes
 */

#ifndef ACE_API_COMMON_H
#define ACE_API_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

// --------------- Boolean type and errors -------------------------------------

/*
 * Order and values of enum constants are part of API
 */
typedef enum
{
    ACE_FALSE,
    ACE_TRUE
} ace_bool_t;

typedef enum
{
    ACE_OK,                 // Operation succeeded
    ACE_INVALID_ARGUMENTS,  // Invalid input parameters
    ACE_INTERNAL_ERROR,     // ACE internal error
    ACE_ACE_UNKNOWN_ERROR   // Unexpected operation
} ace_return_t;

// --------------- Basic types -------------------------------------------------

typedef size_t  ace_size_t;
typedef char*   ace_string_t;           // NULL-terminated string
typedef int     ace_widget_handle_t;
typedef char*   ace_resource_t;
typedef char*   ace_subject_t;
typedef char*   ace_session_id_t;
typedef void*   ace_private_data_t;

// --------------- Access requests ---------------------------------------------

typedef struct
{
    ace_size_t        count;
    ace_string_t*     items;
} ace_feature_list_t;

typedef struct
{
    ace_string_t name;
    ace_string_t value;
} ace_param_t;

typedef struct
{
    ace_size_t      count;
    ace_param_t*    items;
} ace_param_list_t;

typedef struct
{
    ace_string_t     name;
    ace_param_list_t param_list;
} ace_dev_cap_t;

typedef struct
{
    ace_size_t        count;
    ace_dev_cap_t*    items;
} ace_dev_cap_list_t;

typedef struct
{
    ace_session_id_t    session_id;         // DEPRECATED will be removed
    ace_widget_handle_t widget_handle;      // DEPRECATED will be removed
    ace_feature_list_t  feature_list;
    ace_dev_cap_list_t  dev_cap_list;
} ace_request_t;

// --------------- Popup data types --------------------------------------------

/*
 * Popup types that can be requested to be displayed by ACE
 */
typedef enum
{
    ACE_ONESHOT,
    ACE_SESSION,
    ACE_BLANKET
} ace_popup_t;

/*
 * Validity of answer that can be returned by ACE popup
 */
typedef enum
{
    ACE_ONCE,
    ACE_PER_SESSION,
    ACE_ALWAYS
} ace_validity_t;

#ifdef __cplusplus
}
#endif

#endif // ACE_API_COMMON_H
