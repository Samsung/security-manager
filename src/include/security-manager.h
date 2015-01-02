/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        security-manager.h
 * @author      Pawel Polawski (p.polawski@samsung.com)
 * @version     1.0
 * @brief       This file contains header of security-manager API
 */

#ifndef SECURITY_MANAGER_H_
#define SECURITY_MANAGER_H_

#include <sys/types.h>

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
};

/*! \brief accesses types for application installation paths*/
enum app_install_path_type {
    //accessible read-write only for applications with same package id
    SECURITY_MANAGER_PATH_PRIVATE,
    //read-write access for all applications
    SECURITY_MANAGER_PATH_PUBLIC,
    //read only access for all applications
    SECURITY_MANAGER_PATH_PUBLIC_RO,
    //accessible for writing to all apps within its package
    SECURITY_MANAGER_PATH_RW,
    //accessible to apps for reading
    SECURITY_MANAGER_PATH_RO,
    //this is only for range limit
    SECURITY_MANAGER_ENUM_END
};

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

/**
 * This function translates lib_retcode error codes to strings describing
 * errors.
 * @param[in] rc error code of lib_retcode type
 * @return string describing error for error code
 */
const char *security_manager_strerror(enum lib_retcode rc);

/*
 * This function is responsible for initialize app_inst_req data structure
 * It uses dynamic allocation inside and user responsibility is to call
 * app_inst_req_free() for freeing allocated resources
 *
 * \param[in] Address of pointer for handle app_inst_req structure
 * \return API return code or error code
 */
int security_manager_app_inst_req_new(app_inst_req **pp_req);

/*
 * This function is used to free resources allocated by calling app_inst_req_new()
 *  \param[in] Pointer handling allocated app_inst_req structure
 */
void security_manager_app_inst_req_free(app_inst_req *p_req);

/*
 * This function is used to set up application identifier in app_inst_req structure
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] Application identifier
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_app_id(app_inst_req *p_req, const char *app_id);

/*
 * This function is used to set up package identifier in app_inst_req structure
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] Package identifier
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_pkg_id(app_inst_req *p_req, const char *pkg_id);

/*
 * This function is used to add privilege to app_inst_req structure,
 * it can be called multiple times
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] Application privilager
 * \return API return code or error code
 */
int security_manager_app_inst_req_add_privilege(app_inst_req *p_req, const char *privilege);

/*
 * This function is used to add application path to app_inst_req structure,
 * it can be called multiple times
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] Application path
 * \param[in] Application path type
 * \return API return code or error code
 */
int security_manager_app_inst_req_add_path(app_inst_req *p_req, const char *path, const int path_type);

/*
 * This function is used to set up user identifier in app_inst_req structure.
 * This field simplifies support for online and offline modes.
 *
 * \param[in] Pointer handling app_inst_req structure
 * \param[in] User identifier (UID)
 * \return API return code or error code
 */
int security_manager_app_inst_req_set_uid(app_inst_req *p_req,
                                          const uid_t uid);

/*
 * This function is used to install application based on
 * using filled up app_inst_req data structure
 *
 * \param[in] Pointer handling app_inst_req structure
 * \return API return code or error code: it would be
 * - SECURITY_MANAGER_SUCCESS on success,
 * - SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED when user does not
 * have rights to install requested directories,
 * - SECURITY_MANAGER_ERROR_UNKNOWN on other errors.
 */
int security_manager_app_install(const app_inst_req *p_req);

/*
 * This function is used to uninstall application based on
 * using filled up app_inst_req data structure
 *
 * \param[in] Pointer handling app_inst_req structure
 * \return API return code or error code
 */
int security_manager_app_uninstall(const app_inst_req *p_req);

/**
 * Get package id of a given application
 *
 * On successful call pkg_id should be freed by the caller using free() function
 *
 * \param[out] Pointer to package identifier string
 * \param[in]  Application identifier
 * \return API return code or error code
 */
int security_manager_get_app_pkgid(char **pkg_id, const char *app_id);

/**
 * Compute smack label for given application id and set it for
 * currently running process
 *
 * \param[in] Application identifier
 * \return API return code or error code
 */
int security_manager_set_process_label_from_appid(const char *app_id);

/**
 * For given app_id and current user, calculate allowed privileges that give
 * direct access to file system resources. Then add current process to
 * supplementary groups that are assigned to these resources.
 *
 * In Tizen some sensitive resources are being accessed by applications directly.
 * The resources, being file system objects, are owned by dedicated GIDs and only
 * processes in those UNIX groups can access them. This function is used for
 * adding application process to all permitted groups that are assigned to such
 * privileges.
 *
 * \param[in] Application identifier
 * \return API return code or error code
 */
int security_manager_set_process_groups_from_appid(const char *app_id);

/**
 * The above launcher functions, manipulating process Smack label and group,
 * require elevated privileges. Since they will be called by launcher after fork,
 * in the process for the application, privileges should be dropped before
 * running an actual application. This function is a helper for that purpose -
 * it drops capabilities from the process.
 *
 * \return API return code or error code
 */
int security_manager_drop_process_privileges(void);

/**
 * A convenience function for launchers for preparing security context for an
 * application process. It should be called after fork in the new process, before
 * running the application in it.
 * It is aimed to cover most common cases and will internally call other, more
 * specialized security-manager functions for launchers.
 * Currently it just calls:
 * - security_manager_set_process_label_from_appid
 * - security_manager_set_process_groups_from_appid
 * - security_manager_drop_process_privileges
 *
 * \param[in] Application identifier
 * \return API return code or error code
 */
int security_manager_prepare_app(const char *app_id);

/*
 * This function is responsible for initialization of user_req data structure.
 * It uses dynamic allocation inside and user responsibility is to call
 * security_manager_user_req_free() for freeing allocated resources.
 *
 * @param[in] Address of pointer for handle user_req structure
 * @return API return code or error code
 */
int security_manager_user_req_new(user_req **pp_req);

/*
 * This function is used to free resources allocated by
 * security_manager_user_req_new()
 *
 * @param[in] Pointer handling allocated user_req structure
 */
void security_manager_user_req_free(user_req *p_req);

/*
 * This function is used to set up user identifier in user_req structure.
 *
 * @param p_req Structure containing user data filled during this function call
 * @param uid User identifier to be set
 * @return API return code or error code
 */
int security_manager_user_req_set_uid(user_req *p_req, uid_t uid);

/*
 * This function is used to set up user type in user_req structure.
 *
 * @param p_req Structure containing user data filled during this function call
 * @param utype User type to be set
 * @return API return code or error code
 */
int security_manager_user_req_set_user_type(user_req *p_req, security_manager_user_type utype);

/*
 * This function should be called to inform security-manager about adding new user.
 * This function succeeds only when is called by privileged user.
 * Otherwise it just returns SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED and does nothing.
 *
 * It adds all required privileges to a newly created user.
 * User data are passed through  pointer 'p_req'.
 * @param p_req Structure containing user data filled before calling this
 * uid and user type needs to be filled in p_req structure,
 * otherwise SECURITY_MANAGER_ERROR_INPUT_PARAM will be returned.
 * @return API return code or error code.
 */
int security_manager_user_add(const user_req *p_req);

/*
 * This function should be called to inform security-manager about removing a user.
 * This function succeeds only when is called by privileged user.
 * Otherwise it just returns SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED and does nothing.
 *
 * It removes all privileges granted to a user that has been granted previously by
 * security_manager_user_add.
 *
 * @param p_req Structure containing user data filled before calling this.
 * uid of user needs to be filled in p_req structure,
 * otherwise SECURITY_MANAGER_ERROR_INPUT_PARAM will be returned.
 * @return API return code or error code
 */
int security_manager_user_delete(const user_req *p_req);

/**
 * \brief This function is responsible for initializing policy_update_req data structure.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * policy_update_req_free() for freeing allocated resources.
 *
 * \param[out] pp_req Address of pointer for handle policy_update_req structure
 * \return API return code or error code
 */
int security_manager_policy_update_req_new(policy_update_req **pp_req);

/**
 * \brief This function is used to free resources allocated by calling policy_update_req_new().
 * \param[in] p_req Pointer handling allocated policy_update_req structure
 */
void security_manager_policy_update_req_free(policy_update_req *p_req);

/**
 * \brief This function is responsible for initializing policy_entry data structure.
 *
 * It uses dynamic allocation inside and user responsibility is to call
 * policy_policy_entry_free() for freeing allocated resources.
 *
 * \note application and privilege fields default to SECURITY_MANAGER_ANY wildcard,
 *       user field defaults to calling user's UID, whereas the current and max level
 *       values, default to empty string "".
 *
 * \param[out] pp_entry Address of pointer for handle policy_entry structure
 * \return API return code or error code
 */
int security_manager_policy_entry_new(policy_entry **pp_entry);

/**
 * \brief This function is used to free resources allocated by calling
 * policy_entry_req_new().
 * \param[in] p_entry Pointer handling allocated policy_entry structure
 */
void security_manager_policy_entry_free(policy_entry *p_entry);

/**
 * This function is used to set up application identifier in p_entry structure
 *
 * \param[in] p_entry Pointer handling policy_entry structure
 * \param[in] app_id Application identifier to be set
 * \return API return code or error code
 */
int security_manager_policy_entry_set_application(policy_entry *p_entry, const char *app_id);

/**
 * This function is used to set up user identifier in p_entry structure
 * Calling this function may be omitted if user wants to set policies for himself
 * \param[in] p_entry Pointer handling policy_entry structure
 * \param[in] user_id User identifier to be set
 * \return API return code or error code
 */
int security_manager_policy_entry_set_user(policy_entry *p_entry, const char *user_id);

/**
 * This function is used to set up privilege in p_entry structure
 *
 * \param[in] p_entry Pointer handling policy_entry structure
 * \param[in] privilege Privilege to be set
 * \return API return code or error code
 */
int security_manager_policy_entry_set_privilege(policy_entry *p_entry, const char *privilege);

/**
 * This function is used to set up privilege level in p_entry structure.
 * This api is intended to be used to decrease user's own level of privilege.
 *
 * \param[in] p_entry Pointer handling policy_entry structure
 * \param[in] policy_level Policy level to be set. The level of privilege may
 * be one of strings returned by @ref security_manager_policy_levels_get.
 * If it is not, then error code SECURITY_MANAGER_ERROR_INPUT_PARAM is returned.
 * Two predefined values are always valid here:
 *
 * "Allow", which means that user allows some app (setup by calling function
 * @ref security_manager_policy_entry_set_application) to run with some privilege
 * (setup by @ref security_manager_policy_entry_set_privilege).
 * Note, that this not necessarily mean, that this privilege will really be granted.
 * Final decision of granting privilege also depends on app's manifests,
 * predefined policy and administrator's or manufacturer's settings.
 * If all of those policy sources also allows granting privilege for that app,
 *  then (and only then) it will be granted.
 *
 * "Deny", which means that user disallows some app (setup by calling function
 * @ref security_manager_policy_entry_set_application) to run with some privilege
 * (setup by @ref security_manager_policy_entry_set_privilege).
 * Note, that this denies privilege irrespective of privilege levels granted
 * to app by other policy sources: app's manifests, predefined policy
 * and administrator's or manufacturer's settings.
 *
 * Other levels may be also valid, if returned by security_manager_policy_levels_get.
 * They represent other policy levels configured in system, which security-manager
 * does support. The other levels are always something between "Allow" and "Deny"
 * (like "Allow only once").
 *
 * Irrespective of a meaning of those values security-manager will always treat
 * policy set by security_manager_policy_entry_set_level as a mean to
 * decrease user's own rights. This will never increase overall policy.
 *
 * \return API return code or error code
 */
int security_manager_policy_entry_set_level(policy_entry *p_entry, const char *policy_level);

/**
 * This function is used to set up privilege level for admin policy entries
 * in p_entry structure.
 *
 * This function is intended to be used by admin to change level of privilege.
 * If it is used by user that has no http://tizen.org/privilege/systemsettings.admin
 * privilege, then security_manager_policy_update_send will return error code.
 *
 * \param[in] p_entry Pointer handling policy_entry structure
 * \param[in] policy_level Policy level to be set. This may be one of strings
 * returned by @ref security_manager_policy_levels_get. If it is not, then error
 * code is returned (SECURITY_MANAGER_ERROR_INPUT_PARAM).
 * Two predefined values are always valid here:
 *
 * "Allow", which means that admin allows some user's app to
 * get privilege irrespective of predefined policy settings for that user.
 * Note, that this not necessarily mean, that this privilege will really be granted.
 * Final decision of granting privilege also depends on app's manifests,
 * user's own policy (set up by @ref security_manager_policy_entry_set_level)
 * or manufacturer's settings.
 * If all of those policy sources also allows granting privilege for that app,
 * then (and only then) it will be granted.
 *
 * "Deny", which means that admin disallows some user's app to get privilege
 * irrespective of predefined policy settings for that user.
 * Note, that this denies privilege app's manifests, user's own policy
 * (set up by @ref security_manager_policy_entry_set_level) or manufacturer's
 * settings.
 *
 * Other levels may be also valid, if returned by security_manager_policy_levels_get.
 * They represent other policy levels configured in system, which security-manager
 * does support. The other levels are always something between "Allow" and "Deny"
 * (like "Allow only once").
 *
 * Irrespective of a meaning of those values security-manager will always treat
 * policy set by security_manager_policy_entry_admin_set_level as a mean for admin
 * to change user's rights, but will not alter user's own privilege level set up
 * by @ref security_manager_policy_entry_set_level.
 *
 * \return API return code or error code
 */
int security_manager_policy_entry_admin_set_level(policy_entry *p_entry, const char *policy_level);

/**
 * This function is used to add policy entry to policy update request.
 *
 * Note, that this function does not make a copy of object pointed to by p_entry
 * and does not change owner of this handler.
 * User is responsible to keep p_entry untouched until @ref security_manager_policy_update_send
 * is called on p_req. After that p_entry still needs to be freed.
 * (see examples in documentation of @ref security_manager_policy_update_send)
 *
 * \param[in] p_req Pointer handling allocated policy_update_req structure
 * \param[in] p_entry Pointer handling policy_entry structure
 * \return API return code or error code
 */
int security_manager_policy_update_req_add_entry(policy_update_req *p_req, const policy_entry *p_entry);

/**
 * This function is used to obtain user ID from p_entry structure
 *
 * \param[in] p_entry Pointer handling policy_entry structure
 * \attention Warning: returned pointer to user ID is valid as long as p_entry is valid.
 *
 * \return user uid
 */

const char *security_manager_policy_entry_get_user(policy_entry *p_entry);
/**
 * This function is used to obtain application name from p_entry structure
 *
 * \param[in] p_entry Pointer handling policy_entry structure
 * \attention Warning: returned pointer to application name is valid as long as p_entry is valid.
 *
 * \return application name
 */

const char *security_manager_policy_entry_get_application(policy_entry *p_entry);
/**
 * This function is used to obtain privilege name from p_entry structure
 *
 * \param[in] p_entry Pointer handling policy_entry structure
 * \attention Warning: returned pointer to privilege name is valid as long as p_entry is valid.
 *
 * \return privilege name
 */
const char *security_manager_policy_entry_get_privilege(policy_entry *p_entry);
/**
 * This function is used to obtain current policy level from p_entry structure
 *
 * \param[in] p_entry Pointer handling policy_entry structure
 * \attention Warning: returned pointer to policy level is valid as long as p_entry is valid.
 *
 * \return Current policy level
 */
const char *security_manager_policy_entry_get_level(policy_entry *p_entry);

/**
 * This function is used to obtain maximal policy level from p_entry structure
 *
 * \param[in] p_entry Pointer handling policy_entry structure.
 * \attention Warning: returned pointer to maximal policy level is valid as long as p_entry is valid.
 *
 * \return Maximal policy level
 */
const char *security_manager_policy_entry_get_max_level(policy_entry *p_entry);

/**
 * \brief This function is used to send the prepared policy update request using privacy manager
 *        entry point. The request should contain at least one policy update unit, otherwise
 *        the SECURITY_MANAGER_ERROR_INPUT_PARAM is returned.
 *
 * \note  1. If user field in policy_entry is empty, then uid of the calling user is assumed
 *        2. If privilege or app field in policy_entry is empty, then SECURITY_MANAGER_API_BAD_REQUEST
 *           is returned
 *        3. For user's personal policy: wildcards usage in application or privilege field of policy_entry
 *           is not allowed
 *
 * \param[in] p_req Pointer handling allocated policy_update_req structure
 * \return API return code or error code
 *
 * Example:
 * (warning: checking return codes are omitted in examples just for visibility reasons)
 *
 * - to update policy for user by himself:
 *   (Deny access from app MyApp1 to privilege http://tizen.org/privilege/systemsettings,
 *   deny access from app MyApp2 to privilege http://tizen.org/privilege/systemsettings,
 *   deny access from app MyApp3 to privilege http://tizen.org/privilege/notificationmanager)
 *
 *      policy_update_req *policy_update_request;
 *      policy_entry *entry1;
 *      policy_entry *entry2;
 *      policy_entry *entry3;
 *
 *      security_manager_policy_update_req_new(&policy_update_request);
 *      security_manager_policy_entry_new(&entry1);
 *      security_manager_policy_entry_new(&entry2);
 *      security_manager_policy_entry_new(&entry3);
 *
 *      security_manager_policy_entry_set_application(entry1, "MyApp1");
 *      security_manager_policy_entry_set_privilege(entry1, "http://tizen.org/privilege/systemsettings");
 *      security_manager_policy_entry_set_level(entry1, "Deny");
 *
 *      security_manager_policy_entry_set_application(entry2, "MyApp2");
 *      security_manager_policy_entry_set_privilege(entry2, "http://tizen.org/privilege/systemsettings");
 *      security_manager_policy_entry_set_level(entry2, "Deny");
 *
 *      security_manager_policy_entry_set_application(entry3, "MyApp3");
 *      security_manager_policy_entry_set_privilege(entry3, "http://tizen.org/privilege/notificationmanager");
 *      security_manager_policy_entry_set_level(entry3, "Deny");
 *
 *      security_manager_policy_update_req_add_entry(policy_update_request, entry1);
 *      security_manager_policy_update_req_add_entry(policy_update_request, entry2);
 *      security_manager_policy_update_req_add_entry(policy_update_request, entry3);
 *
 *      //do not change entry1, entry2 or entry3!
 *
 *      security_manager_policy_update_send(policy_update_request);
 *
 *      security_manager_policy_entry_free(entry1);
 *      security_manager_policy_entry_free(entry2);
 *      security_manager_policy_entry_free(entry3);
 *      security_manager_policy_update_free(policy_update_request);
 *
 * - to update policy by administrator for some user:
 *   (Deny access of user of uid 2001 from any app to privilege http://tizen.org/privilege/vibrator,
 *   (allow access of user of uid 2002 using app "App1" to privilege http://tizen.org/privilege/email.admin)
 *
 *      policy_update_req *policy_update_request;
 *
 *      security_manager_policy_update_req_new(&policy_update_request);

 *      policy_entry *entry1;
 *      policy_entry *entry2;
 *      char *adminswife = "2001";
 *      char *adminsfriend = "2002";
 *
 *      security_manager_policy_entry_new(&entry1);
 *      security_manager_policy_entry_new(&entry2);
 *
 *      security_manager_policy_entry_set_user(entry1, adminswife);
 *      security_manager_policy_entry_set_application(entry1, SECURITY_MANAGER_ANY);
 *      security_manager_policy_entry_set_privilege(entry1, "http://tizen.org/privilege/vibrator");
 *      security_manager_policy_entry_admin_set_level(entry1, "Deny");
 *
 *      security_manager_policy_entry_set_user(entry2, adminsfriend);
 *      security_manager_policy_entry_set_application(entry2, "App1");
 *      security_manager_policy_entry_set_privilege(entry2, "http://tizen.org/privilege/email.admin");
 *      security_manager_policy_entry_admin_set_level(entry2, "Allow");
 *
 *      security_manager_policy_update_req_add_entry(policy_update_request, entry1);
 *      security_manager_policy_update_req_add_entry(policy_update_request, entry2);
 *
 *      //do not change entry1 or entry2!
 *
 *      security_manager_policy_update_send(policy_update_request);
 *
 *      security_manager_policy_entry_free(entry1);
 *      security_manager_policy_entry_free(entry2);
 *      security_manager_policy_update_free(policy_update_request);
 *
 */
int security_manager_policy_update_send(policy_update_req *p_req);

/**
 * \brief Function fetches all privileges enforced by admin user.
 *        The result is stored in the policy_entry structures array.
 *
 * \note It should be called by user with http://tizen.org/privilege/systemsettings.admin privilege.
 *       Normal users may list their personal policy entries using
 *       security_manager_get_configured_policy_for_self() API function.
 *
 * \attention Developer is responsible for calling security_manager_policy_entries_free()
 *            for freeing allocated resources.
 *
 * \param[in]  p_filter        Pointer to filter struct
 * \param[out] ppp_privs_policy Pointer handling allocated policy_entry structures array
 * \param[out] p_size          Pointer where the size of allocated array will be stored
 * \return API return code or error code
 */
int security_manager_get_configured_policy_for_admin(
        policy_entry *p_filter,
        policy_entry ***ppp_privs_policy,
        size_t *p_size);

/**
 * \brief Function fetches all privileges that are configured by user in his/her
 *        privacy manager. The result is stored in the policy_entry structures array.
 *        User may only fetch privileges for his/her own UID.
 *
 * \attention Developer is responsible for calling security_manager_policy_entries_free()
 *            for freeing allocated resources.
 *
 * \param[in]  p_filter        Pointer to filter struct
 * \param[out] ppp_privs_policy Pointer handling allocated policy_entry structures array
 * \param[out] p_size          Pointer where the size of allocated array will be stored
 * \return API return code or error code
 */
int security_manager_get_configured_policy_for_self(
        policy_entry *p_filter,
        policy_entry ***ppp_privs_policy,
        size_t *p_size);

/**
 * \brief Function gets the whole policy for all users, their applications and privileges
 *        based on the provided filter. The result is stored in the policy_entry array.
 *
 * \note If this call is performed by user with http://tizen.org/privilege/systemsettings.admin
 *       privilege, then it's possible to list policies for all users.
 *       Normal users may only list privileges for their own UID.
 *
 * \attention Developer is responsible for calling security_manager_policy_entries_free()
 *            for freeing allocated resources.
 *
 * \param[in]  p_filter        Pointer to filter struct
 * \param[out] ppp_privs_policy Pointer handling allocated policy_entry structures array
 * \param[out] p_size          Pointer where the size of allocated array will be stored
 * \return API return code or error code
 */
int security_manager_get_policy(
        policy_entry *p_filter,
        policy_entry ***ppp_privs_policy,
        size_t *p_size);

/**
 *  \brief This function is used to free resources allocated in policy_entry structures array.
 *  \param[in] p_entries Pointer handling allocated policy status array
 *  \param[in] size      Size of the array
 */
void security_manager_policy_entries_free(policy_entry *p_entries, const size_t size);

/**
 * This function returns array of available policy levels in form of simple
 * text descriptions. List is sorted using internal policy level value,
 * from lowest value to highest and starts with "Deny".
 *
 * Caller needs to free memory allocated for the list using
 * security_manager_policy_levels_free().
 *
 * @param levels pointer to array of strings.
 * @param levels_count number of strings in levels array.
 * @return API return code or error code.
 */
int security_manager_policy_levels_get(char ***levels, size_t *levels_count);

/**
 * This function free memory allocated by security_manager_policy_levels_get()
 * function.
 *
 * @param levels array of strings returned by
 * security_manager_policy_levels_get() function.
 * @return API return code or error code.
 */
void security_manager_policy_levels_free(char **levels, size_t levels_count);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_MANAGER_H_ */
