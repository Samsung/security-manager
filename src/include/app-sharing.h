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

#ifndef SECURITY_MANAGER_APP_SHARING_H_
#define SECURITY_MANAGER_APP_SHARING_H_

#include "security-manager-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function is responsible for initialize private_sharing_req data structure
 * It uses dynamic allocation inside and user responsibility is to call
 * private_sharing_req_free() for freeing allocated resources
 *
 * \param[out] pp_req  Address of pointer for handle private_sharing_req structure
 * \return API return code or error code
 */
int security_manager_private_sharing_req_new(private_sharing_req **pp_req);

/**
 * This function is used to free resources allocated by calling private_sharing_req_new()
 *
 * \param[in] p_req  Pointer handling allocated app_inst_req structure
 */
void security_manager_private_sharing_req_free(private_sharing_req *p_req);

/**
 * This function is used to set up package identifier of paths owner application
 * in private_sharing_req structure
 *
 * \param[in] p_req   Pointer handling private_sharing_req structure
 * \param[in] app_id  Application identifier
 * \return API return code or error code: it would be
 * - SECURITY_MANAGER_SUCCESS on success,
 * - SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE when either owner app_id, target app_id
 *   or paths are not set,
 * - SECURITY_MANAGER_ERROR_UNKNOWN on other errors.
 */
int security_manager_private_sharing_req_set_owner_appid(private_sharing_req *p_req,
                                                         const char *app_id);

/**
 * This function is used to set up package identifier of sharing target application
 * in private_sharing_req structure
 *
 * \param[in] p_req   Pointer handling private_sharing_req structure
 * \param[in] app_id  Application identifier
 * \return API return code or error code
 */
int security_manager_private_sharing_req_set_target_appid(private_sharing_req *p_req,
                                                          const char *app_id);

/**
 * This function is used to add path list to be shared in private_sharing_req structure
 *
 * \param[in] p_req       Pointer handling private_sharing_req structure
 * \param[in] pp_paths    Path list
 * \param[in] path_count  Path count
 * \return API return code or error code
 */
int security_manager_private_sharing_req_add_paths(private_sharing_req *p_req,
                                                   const char **pp_paths,
                                                   size_t path_count);

/**
 * This function is used to apply private sharing based on given private_sharing_req.
 * One path can be shared with multiple applications at the same time.
 *
 * Required privileges:
 * - http://tizen.org/privilege/notexist
 *
 * \param[in] p_req  Pointer handling private_sharing_req structure
 * \return API return code or error code: it would be
 * - SECURITY_MANAGER_SUCCESS on success,
 * - SECURITY_MANAGER_ERROR_INPUT_PARAM when either owner app_id, target app_id or paths are not set,
 * - SECURITY_MANAGER_ERROR_UNKNOWN on other errors.
 */
int security_manager_private_sharing_apply(const private_sharing_req *p_req);

/**
 * This function is used to drop private sharing based on given private_sharing_req.
 *
 * Required privileges:
 * - http://tizen.org/privilege/notexist
 *
 * \param[in] p_req  Pointer handling private_sharing_req structure
 * \return API return code or error code: it would be
 * - SECURITY_MANAGER_SUCCESS on success,
 * - SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE when either owner app_id, target app_id
 *   or paths are not set,
 * - SECURITY_MANAGER_ERROR_UNKNOWN on other errors.
 */
int security_manager_private_sharing_drop(const private_sharing_req *p_req);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_MANAGER_APP_SHARING_H_ */
