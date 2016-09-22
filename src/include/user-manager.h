/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 */

#pragma once

#include "security-manager-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function is responsible for initialization of user_req data structure.
 * It uses dynamic allocation inside and user responsibility is to call
 * security_manager_user_req_free() for freeing allocated resources.
 *
 * \param[in] pp_req  Address of pointer for handle user_req structure
 * \return API return code or error code
 */
int security_manager_user_req_new(user_req **pp_req);

/**
 * This function is used to free resources allocated by
 * security_manager_user_req_new()
 *
 * \param[in] p_req  Pointer handling allocated user_req structure
 */
void security_manager_user_req_free(user_req *p_req);

/**
 * This function is used to set up user identifier in user_req structure.
 *
 * \param p_req  Structure containing user data filled during this function call
 * \param uid    User identifier to be set
 * \return API return code or error code
 */
int security_manager_user_req_set_uid(user_req *p_req, uid_t uid);

/**
 * This function is used to set up user type in user_req structure.
 *
 * \param p_req  Structure containing user data filled during this function call
 * \param utype  User type to be set
 * \return API return code or error code
 */
int security_manager_user_req_set_user_type(user_req *p_req, security_manager_user_type utype);

/**
 * This function should be called to inform security-manager about adding new user.
 * This function succeeds only when is called by privileged user.
 * Otherwise it just returns SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED and does nothing.
 *
 * Required privileges:
 * - http://tizen.org/privilege/internal/usermanagement
 *
 * It adds all required privileges to a newly created user.
 * User data are passed through  pointer 'p_req'.
 *
 * \param p_req  Structure containing user data filled before calling this
 *               uid and user type needs to be filled in p_req structure,
 *               otherwise SECURITY_MANAGER_ERROR_INPUT_PARAM will be returned.
 * \return API return code or error code.
 */
int security_manager_user_add(const user_req *p_req);

/**
 * This function should be called to inform security-manager about removing a user.
 * This function succeeds only when is called by privileged user.
 * Otherwise it just returns SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED and does nothing.
 *
 * Required privileges:
 * - http://tizen.org/privilege/internal/usermanagement
 *
 * It removes all privileges granted to a user that has been granted previously by
 * security_manager_user_add.
 *
 * \param p_req  Structure containing user data filled before calling this.
 *               uid of user needs to be filled in p_req structure,
 *               otherwise SECURITY_MANAGER_ERROR_INPUT_PARAM will be returned.
 * \return API return code or error code
 */
int security_manager_user_delete(const user_req *p_req);

#ifdef __cplusplus
}
#endif
