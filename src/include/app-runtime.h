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
 * Get package id of a given application
 *
 * On successful call pkg_id should be freed by the caller using free() function
 *
 * \param[out] pkg_id  Pointer to package identifier string
 * \param[in]  app_id  Application identifier
 * \return API return code or error code
 */
int security_manager_get_app_pkgid(char **pkg_id, const char *app_id);

/**
 * Compute smack label for given application id and set it for
 * currently running process
 *
 * \param[in] app_id  Application identifier
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
 * \param[in] app_id  Application identifier
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
 * \param[in] app_id  Application identifier
 * \return API return code or error code
 */
int security_manager_prepare_app(const char *app_id);

/**
 * This function returns array of groups bound to privileges of file resources.
 *
 * Caller needs to free memory allocated for the list using
 * security_manager_groups_free().
 *
 * @param[out] groups pointer to array of strings.
 * @param[out] groups_count number of strings in levels array.
 * @return API return code or error code.
 */
int security_manager_groups_get(char ***groups, size_t *groups_count);

/**
 * This function returns array of groups bound to privileges, the process
 * run by particular user should get.
 *
 * Caller needs to free memory allocated for the list using
 * security_manager_groups_free().
 *
 * @param[in] uid uid for user running the process
 * @param[out] groups pointer to array of group names
 * @param[out] groups_count number of strings in levels array
 * @return API return code or error code.
 */
int security_manager_groups_get_for_user(uid_t uid, char ***groups, size_t *groups_count);

/**
 * This function frees memory allocated by security_manager_groups_get()
 * function.
 *
 * @param[in] groups array of strings returned by security_manager_groups_get() function.
 * @param[in] groups_count size of the groups array
 */
void security_manager_groups_free(char **groups, size_t groups_count);

/**
 * Get package and application id of an application with given socket descriptor
 *
 * On successful call pkg_id and app_id should be freed when caller is done with them.
 * Both pkg_id and app_id are allocated with malloc() so they should be freed with free() function.
 * Either app_id or pkg_id may be NULL. NULL-ed argument will be ignored.
 * If both app_id and pkg_id are NULL then SECURITY_MANAGER_ERROR_INPUT_PARAM will be returned.
 * When socket descriptor is incorrect or not related to any package, this function will
 * return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT.
 * If process on the other side is a nonhybrid application, no app_id will be available.
 *
 * \note For non hybrid applications only package id can be returned
 *
 * \param[in]   sockfd  Socket descriptor of wanted application
 * \param[out]  pkg_id  Package id of the application
 * \param[out]  app_id  Application id of the application
 * \return API return code or error code
 */
int security_manager_identify_app_from_socket(int sockfd, char **pkg_id, char **app_id);

/**
 * Get package and application id of an application with given process identifier
 *
 * On successful call pkg_id and app_id should be freed when caller is done with them.
 * Both pkg_id and app_id are allocated with malloc() so they should be freed with free() function.
 * Either app_id or pkg_id may be NULL. NULL-ed argument will be ignored.
 * If both app_id and pkg_id are NULL then SECURITY_MANAGER_ERROR_INPUT_PARAM will be returned.
 * When process identifier is incorrect or not related to any package, this function will
 * return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT.
 * If given process is a nonhybrid application, no app_id will be available.
 *
 * \note Caller must be able to access and read file /proc/PID/atrr/current where PID is the given
 * process identifier.
 *
 * \note For non hybrid applications only package id can be returned
 *
 * \param[in]   pid     Process identifier of wanted application
 * \param[out]  pkg_id  Package id of the application
 * \param[out]  app_id  Application id of the application
 * \return API return code or error code
 */
int security_manager_identify_app_from_pid(pid_t pid, char **pkg_id, char **app_id);

/**
 * Get package and application id of an application with given process Cynara client identifier
 *
 * On successful call pkg_id and app_id should be freed when caller is done with them.
 * Both pkg_id and app_id are allocated with malloc() so they should be freed with free() function.
 * Either app_id or pkg_id may be NULL. NULL-ed argument will be ignored.
 * If both app_id and pkg_id are NULL then SECURITY_MANAGER_ERROR_INPUT_PARAM will be returned.
 * When process identifier is incorrect or not related to any package, this function will
 * return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT.
 *
 * \note For non hybrid applications only package id can be returned
 *
 * \param[in]   client  Application Cynara client identifier
 * \param[out]  pkg_id  Package id of the application
 * \param[out]  app_id  Application id of the application
 * \return API return code or error code
 */
int security_manager_identify_app_from_cynara_client(const char *client, char **pkg_id,
                                                     char **app_id);
/**
 * Check whether an application would have access to a privilege
 *
 * This enables queries for application's privileges when there is no application
 * process running. In such case the application label cannot be determined from
 * the process and the query for privilege must be based on app_id.
 *
 * The check result is placed in \b result:
 * - 0: access denied
 * - 1: access granted
 *
 * \param[in]  app_id     Application identifier
 * \param[in]  privilege  Privilege name
 * \param[in]  uid        User identifier
 * \param[out] result     Placeholder for result
 * \return API return code or error code
 */
int security_manager_app_has_privilege(const char *app_id, const char *privilege,
                                       uid_t uid, int *result);

/**
 * This function creates descriptor that may be used as shared memory segment
 * with app_id application.
 *
 * \param[in]  name       This value is passed to shm_open as first parameter (man 3 shm_open for details)
 * \param[in]  oflag      This value is passed to shm_open as second parameter (man 3 shm_open for details)
 * \param[in]  mode       This value is passed to shm_open as third parameter (man 3 shm_open for details)
 * \param[in]  app_id     Identifier of application that will gain access to shared memory segment
 * \return file descriptor or -1 on error. If -1 is returned then errno will be set. Errno == ECONNABORTED
 *                        means that the security-manager server failed and did not return any information
 *                        about error.
 */
int security_manager_shm_open(const char *name, int oflag, mode_t mode, const char *app_id);

#ifdef __cplusplus
}
#endif
