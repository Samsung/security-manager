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

#ifndef SECURITY_MANAGER_APP_MANAGER_H_
#define SECURITY_MANAGER_APP_MANAGER_H_

#include "security-manager-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function is responsible for initialize app_inst_req data structure
 * It uses dynamic allocation inside and user responsibility is to call
 * app_inst_req_free() for freeing allocated resources
 *
 * \param[in] pp_req  Address of pointer for handle app_inst_req structure
 * \return API return code or error code
 */
int security_manager_app_inst_req_new(app_inst_req **pp_req);

/**
 * This function is used to free resources allocated by calling app_inst_req_new()
 *
 * \param[in] p_req  Pointer handling allocated app_inst_req structure
 */
void security_manager_app_inst_req_free(app_inst_req *p_req);

/**
 * This function is used to set up target Tizen API version for app in app_inst_req structure
 *
 * \param[in] p_req      Pointer handling app_inst_req structure
 * \param[in] tizen_ver  Target Tizen version
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_target_version(app_inst_req *p_req, const char *tizen_ver);

/**
 * This function is used to set up application identifier in app_inst_req structure
 *
 * \param[in] p_req   Pointer handling app_inst_req structure
 * \param[in] app_id  Application identifier
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_app_id(app_inst_req *p_req, const char *app_id);

/**
 * This function is used to set up package identifier in app_inst_req structure
 *
 * \param[in] p_req   Pointer handling app_inst_req structure
 * \param[in] pkg_id  Package identifier
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_pkg_id(app_inst_req *p_req, const char *pkg_id);

/**
 * This function is used to add privilege to app_inst_req structure,
 * it can be called multiple times
 *
 * \param[in] p_req      Pointer handling app_inst_req structure
 * \param[in] privilege  Application privilager
 * \return API return code or error code
 */
int security_manager_app_inst_req_add_privilege(app_inst_req *p_req, const char *privilege);

/**
 * This function is used to add application path to app_inst_req structure,
 * it can be called multiple times.
 *
 * \deprecated This function is deprecated. Use
 *             security_manager_path_req_add_path() instead.
 *
 * \param[in] p_req      Pointer handling app_inst_req structure
 * \param[in] path       Application path
 * \param[in] path_type  Application path type
 * \return API return code or error code
 */
int security_manager_app_inst_req_add_path(
        app_inst_req *p_req,
        const char *path,
        const int path_type) __attribute__((deprecated(
                "Use security_manager_path_req_add_path() instead")));

/**
 * This function is used to set up user identifier in app_inst_req structure.
 * This field simplifies support for online and offline modes.
 *
 * \param[in] p_req  Pointer handling app_inst_req structure
 * \param[in] uid    User identifier (UID)
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_uid(app_inst_req *p_req,
                                          const uid_t uid);

/**
 * This function is used to set up author identifier in app_inst_req structure.
 * This field is required for trusted paths only (SECURITY_MANAGER_PATH_TRUSTED_RW).
 *
 * \param[in] p_req      Pointer handling app_inst_req structure
 * \param[in] author_id  Author's identifier
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_author_id(app_inst_req *p_req, const char *author_id);

/**
 * This function is used to set up installation type (global, local, preloaded).
 * If type is not set and if installation is performed by global user, type is set to
 * 'SM_APP_INSTALL_GLOBAL'. Otherwise installation type is set to 'SM_APP_INSTALL_LOCAL'.
 *
 * \param[in] p_req  Pointer handling app_inst_req structure
 * \param[in] type   Installation type
 * \return API return code or error code
 *
 */
int security_manager_app_inst_req_set_install_type(app_inst_req *p_req, const enum app_install_type type);

/**
 * This function is used to flag package as hybrid. This must be done consequently for every
 * application installed in package - if first application installed sets this flag, others also
 * must set it, otherwise installation will fail, the same applies to non-hybrid packages -
 * if first application doesn't set this flag, then no other application for this package can set
 * it, otherwise its installation will fail.
 *
 * \param[in] p_req  Pointer handling app_inst_req structure
 * \return API return code or error code
 *
 */
int security_manager_app_inst_req_set_hybrid(app_inst_req *p_req);

/**
 * This function is used to install application based on
 * using filled up app_inst_req data structure
 *
 * Required privileges:
 * - http://tizen.org/privilege/notexist (local installation)
 * - http://tizen.org/privilege/notexist (global installation)
 * - http://tizen.org/privilege/internal/usermanagement (local installation for other users)
 *
 * \param[in] p_req  Pointer handling app_inst_req structure
 * \return API return code or error code: it would be
 * - SECURITY_MANAGER_SUCCESS on success,
 * - SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED when user does not
 * have rights to install requested directories,
 * - SECURITY_MANAGER_ERROR_UNKNOWN on other errors.
 */
int security_manager_app_install(const app_inst_req *p_req);

/**
 * This function is used to uninstall application based on
 * using filled up app_inst_req data structure
 *
 * Required privileges:
 * - http://tizen.org/privilege/notexist (local uninstallation)
 * - http://tizen.org/privilege/notexist (global uninstallation)
 * - http://tizen.org/privilege/internal/usermanagement (local uninstallation for other users)
 *
 * \param[in] p_req  Pointer handling app_inst_req structure
 * \return API return code or error code
 */
int security_manager_app_uninstall(const app_inst_req *p_req);

/**
 * This function is responsible for initialize path_req data structure. It uses
 * dynamic allocation inside and user responsibility is to call
 * security_manager_path_req_free() for freeing allocated resources.
 *
 * \param[in] pp_req    Address of pointer for handle path_req structure
 * \return API return code or error code
 */
int security_manager_path_req_new(path_req **pp_req);

/**
 * This function is used to free resources allocated by calling
 * security_manager_path_req_new().
 *  \param[in] p_req    Pointer handling allocated path_req structure
 */
void security_manager_path_req_free(path_req *p_req);

/**
 * This function is used to set up package identifier in path_req structure.
 *
 * \param[in] p_req     Pointer handling path_req structure
 * \param[in] pkg_id    Package identifier
 * \return API return code or error code
 */
int security_manager_path_req_set_pkg_id(path_req *p_req, const char *pkg_id);

/**
 * This function is used to set up installation type (global, local, preloaded).
 * If type is not set and if installation is performed by global user, type is set to
 * 'SM_APP_INSTALL_GLOBAL'. Otherwise installation type is set to 'SM_APP_INSTALL_LOCAL'.
 *
 * \param[in] p_req     Pointer handling path_req structure
 * \param[in] type      Installation type
 * \return API return code or error code
 */
int security_manager_path_req_set_install_type(path_req *p_req, const enum app_install_type type);

/**
 * This function is used to add a package path to path_req structure. It can be
 * called multiple times.
 *
 * \param[in] p_req     Pointer handling path_req structure
 * \param[in] path      Package path
 * \param[in] path_type Package path type
 * \return API return code or error code
 */
int security_manager_path_req_add_path(path_req *p_req, const char *path, const int path_type);

/**
 * This function is used to set up user identifier in path_req structure.
 * This field simplifies support for online and offline modes.
 *
 * \param[in] p_req     Pointer handling path_req structure
 * \param[in] uid       User identifier (UID)
 * \return API return code or error code
 */
int security_manager_path_req_set_uid(path_req *p_req, const uid_t uid);

/**
 * This function is used to register a set of paths for given package using
 * filled up path_req data structure.
 *
 * Required privileges:
 * - http://tizen.org/privilege/notexist (local installation)
 * - http://tizen.org/privilege/notexist (global installation)
 * - http://tizen.org/privilege/internal/usermanagement (local installation for other users)
 *
 * \param[in] p_req     Pointer handling path_req structure
 *
 * \return API return code or error code: it would be
 * - SECURITY_MANAGER_SUCCESS on success,
 * - SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED when user does not
 * have rights to install requested directories,
 * - SECURITY_MANAGER_ERROR_UNKNOWN on other errors.
 */
int security_manager_paths_register(const path_req *p_req);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_MANAGER_APP_MANAGER_H_ */
