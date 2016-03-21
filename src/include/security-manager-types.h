/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 *	Security Manager library header
 */
/*
 * @file        security-manager-types.h
 * @author      Pawel Polawski (p.polawski@samsung.com)
 * @version     1.0
 * @brief       This file contains header of security-manager API
 */
#ifndef SECURITY_MANAGER_TYPES_H_
#define SECURITY_MANAGER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief return code of API functions */
enum lib_retcode {
    SECURITY_MANAGER_SUCCESS,
    SECURITY_MANAGER_ERROR_UNKNOWN,
    SECURITY_MANAGER_ERROR_INPUT_PARAM,
    SECURITY_MANAGER_ERROR_MEMORY,
    SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE,
    SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED,
    SECURITY_MANAGER_ERROR_ACCESS_DENIED,
    SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT,
    SECURITY_MANAGER_ERROR_APP_UNKNOWN,
    SECURITY_MANAGER_ERROR_APP_NOT_PATH_OWNER,
    SECURITY_MANAGER_ERROR_SOCKET,
    SECURITY_MANAGER_ERROR_BAD_REQUEST,
    SECURITY_MANAGER_ERROR_NO_SUCH_SERVICE,
    SECURITY_MANAGER_ERROR_SERVER_ERROR,
    SECURITY_MANAGER_ERROR_SETTING_FILE_LABEL_FAILED,
};

/*! \brief accesses types for application installation paths*/
enum app_install_path_type {
    //! RO access for all applications
    SECURITY_MANAGER_PATH_PUBLIC_RO,
    //! RW access for given application package
    SECURITY_MANAGER_PATH_RW,
    //! RO access for given application package
    SECURITY_MANAGER_PATH_RO,
    //! RW access for the owner, RO for other 2.X applications
    //! (other 3.0 apps will not have access to the shared folder)
    SECURITY_MANAGER_PATH_OWNER_RW_OTHER_RO,
    //! RW access for application packages coming from the same author
    SECURITY_MANAGER_PATH_TRUSTED_RW,
    //! this is only for range limit
    SECURITY_MANAGER_ENUM_END
};

enum app_install_type : int {
    SM_APP_INSTALL_NONE = 0,
    SM_APP_INSTALL_LOCAL,
    SM_APP_INSTALL_GLOBAL,
    SM_APP_INSTALL_PRELOADED,
    SM_APP_INSTALL_END
};
typedef enum app_install_type app_install_type;

/**
 * This enum has values equivalent to gumd user type.
 * The gum-utils help states that
 * "usertype can be system(1), admin(2), guest(3), normal(4)."
 */
enum security_manager_user_type {
    SM_USER_TYPE_NONE   = 0,/*<-this should not be used, if it is used, there will be an error returned by SM*/
    SM_USER_TYPE_SYSTEM = 1,
    SM_USER_TYPE_ADMIN  = 2,
    SM_USER_TYPE_GUEST  = 3,
    SM_USER_TYPE_NORMAL = 4,
    SM_USER_TYPE_ANY = 5,/*<-this value may be used only for setting policies and not during user adding*/
    SM_USER_TYPE_END
};
typedef enum security_manager_user_type security_manager_user_type;

/*! \brief data structure responsible for handling informations
 * required to install / uninstall application */
struct app_inst_req;
typedef struct app_inst_req app_inst_req;

/*! \brief data structure responsible for handling informations
 * required to manage users */
struct user_req;
typedef struct user_req user_req;

/*! \brief data structure responsible for handling policy updates
 *  required to manage users' and applications' permissions */
struct policy_update_req;
typedef struct policy_update_req policy_update_req;

/*! \brief data structure responsible for handling single policy entry*/
struct policy_entry;
typedef struct policy_entry policy_entry;

/*! brief data structure responsible for handling informations required to apply / drop
 * private sharing between applications */
struct private_sharing_req;
typedef struct private_sharing_req private_sharing_req;

/*! \brief wildcard to be used in requests to match all possible values of given field.
 *         Use it, for example when it is desired to list or apply policy change for all
 *         users or all apps for selected user.
 */
#define SECURITY_MANAGER_ANY "#"

/*! \brief value denoting delete operation on specific policy. It can only be used
 *         in update policy operation, passed to either security_manager_policy_entry_admin_set_level
 *         or security_manager_policy_entry_set_level.
 */
#define SECURITY_MANAGER_DELETE "DELETE"

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_MANAGER_TYPES_H_ */

