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

/**
 * \name Return Codes
 * exported by the foundation API.
 * result codes begin with the start error code and extend into negative direction.
 * @{
*/
#define SECURITY_MANAGER_API_SUCCESS 0
/*! \brief   indicating the result of the one specific API is successful */
#define SECURITY_MANAGER_API_ERROR_SOCKET -1

/*! \brief   indicating the socket between client and Security Manager has been failed  */
#define SECURITY_MANAGER_API_ERROR_BAD_REQUEST -2

/*! \brief   indicating the response from Security Manager is malformed */
#define SECURITY_MANAGER_API_ERROR_BAD_RESPONSE -3

/*! \brief   indicating the requested service does not exist */
#define SECURITY_MANAGER_API_ERROR_NO_SUCH_SERVICE -4

/*! \brief   indicating requesting object is not exist */
#define SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT -6

/*! \brief   indicating the authentication between client and server has been failed */
#define SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED -7

/*! \brief   indicating the API's input parameter is malformed */
#define SECURITY_MANAGER_API_ERROR_INPUT_PARAM -8

/*! \brief   indicating the output buffer size which is passed as parameter is too small */
#define SECURITY_MANAGER_API_ERROR_BUFFER_TOO_SMALL -9

/*! \brief   indicating system  is running out of memory state */
#define SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY -10

/*! \brief   indicating the access has been denied by Security Manager */
#define SECURITY_MANAGER_API_ERROR_ACCESS_DENIED -11

/*! \brief   indicating Security Manager has been failed for some reason */
#define SECURITY_MANAGER_API_ERROR_SERVER_ERROR -12

/*! \brief   indicating getting smack label from socket failed  */
#define SECURITY_MANAGER_API_ERROR_GETTING_SOCKET_LABEL_FAILED -21

/*! \brief   indicating getting smack label from file failed  */
#define SECURITY_MANAGER_API_ERROR_GETTING_FILE_LABEL_FAILED -22

/*! \brief   indicating setting smack label for file failed  */
#define SECURITY_MANAGER_API_ERROR_SETTING_FILE_LABEL_FAILED -23

/*! \brief   indicating file already exists  */
#define SECURITY_MANAGER_API_ERROR_FILE_EXIST -24

/*! \brief   indicating file does not exist  */
#define SECURITY_MANAGER_API_ERROR_FILE_NOT_EXIST -25

/*! \brief   indicating file open error  */
#define SECURITY_MANAGER_API_ERROR_FILE_OPEN_FAILED -26

/*! \brief   indicating file creation error  */
#define SECURITY_MANAGER_API_ERROR_FILE_CREATION_FAILED -27

/*! \brief   indicating file deletion error  */
#define SECURITY_MANAGER_API_ERROR_FILE_DELETION_FAILED -28

/*! \brief   indicating the error with unknown reason */
#define SECURITY_MANAGER_API_ERROR_UNKNOWN -255
/** @}*/


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
    SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED
};

/*! \brief accesses types for application installation paths*/
enum app_install_path_type {
    //accessible read-write only for applications with same package id
    SECURITY_MANAGER_PATH_PRIVATE,
    //read-write access for all applications
    SECURITY_MANAGER_PATH_PUBLIC,
    //read only access for all applications
    SECURITY_MANAGER_PATH_PUBLIC_RO,
    //this is only for range limit
    SECURITY_MANAGER_ENUM_END
};

/*! \brief data structure responsible for handling informations
 * required to install / uninstall application */
struct app_inst_req;
typedef struct app_inst_req app_inst_req;

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
 * Extract smack label from a given binary and set it for
 * currently running process
 *
 * \param[in] Path to binary
 * \return API return code or error code
 */
int security_manager_set_process_label_from_binary(const char *path);

/**
 * Compute smack label for given application id and set it for
 * currently running process
 *
 * \param[in] Application identifier
 * \return API return code or error code
 */
int security_manager_set_process_label_from_appid(const char *app_id);


#ifdef __cplusplus
}
#endif

#endif /* SECURITY_MANAGER_H_ */
