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
 */
/*
 * @file        protocols.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file contains list of all protocols suported by security-manager.
 */

#ifndef _SECURITY_MANAGER_PROTOCOLS_
#define _SECURITY_MANAGER_PROTOCOLS_

#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <dpl/serialization.h>
#include <security-manager.h>

/**
 * \name Return Codes
 * exported by the foundation API.
 * result codes begin with the start error code and extend into negative direction.
 * @{
*/

/*! \brief   indicating the result of the one specific API is successful */
#define SECURITY_MANAGER_API_SUCCESS 0

/*! \brief   indicating the socket between client and Security Manager has been failed  */
#define SECURITY_MANAGER_API_ERROR_SOCKET -1

/*! \brief   indicating the request to Security Manager is malformed */
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

/*! \brief   indicating that application is not present in the database */
#define SECURITY_MANAGER_API_ERROR_APP_UNKNOWN -29

/*! \brief   indicating that application is not owner of path */
#define SECURITY_MANAGER_API_ERROR_APP_NOT_PATH_OWNER -30

/*! \brief   indicating the error with unknown reason */
#define SECURITY_MANAGER_API_ERROR_UNKNOWN -255
/** @}*/


struct app_inst_req {
    std::string appId;
    std::string pkgId;
    std::vector<std::string> privileges;
    std::vector<std::pair<std::string, int>> appPaths;
    uid_t uid;
    std::string tizenVersion;
    std::string authorId;
};

struct user_req {
    uid_t uid;
    int utype;
};

struct private_sharing_req {
    std::string ownerAppId;
    std::string targetAppId;
    std::vector<std::string> paths;
};

namespace SecurityManager {

extern char const * const SERVICE_SOCKET;
extern char const * const MASTER_SERVICE_SOCKET;
extern char const * const SLAVE_SERVICE_SOCKET;

enum class SecurityModuleCall
{
    APP_INSTALL,
    APP_UNINSTALL,
    APP_GET_PKGID,
    APP_GET_GROUPS,
    APP_APPLY_PRIVATE_SHARING,
    APP_DROP_PRIVATE_SHARING,
    USER_ADD,
    USER_DELETE,
    POLICY_UPDATE,
    GET_POLICY,
    GET_CONF_POLICY_ADMIN,
    GET_CONF_POLICY_SELF,
    POLICY_GET_DESCRIPTIONS,
    GET_PRIVILEGES_MAPPING,
    GROUPS_GET,
    APP_HAS_PRIVILEGE,
    NOOP = 0x90,
};

enum class MasterSecurityModuleCall
{
    CYNARA_UPDATE_POLICY,
    CYNARA_USER_INIT,
    CYNARA_USER_REMOVE,
    POLICY_UPDATE,
    GET_CONFIGURED_POLICY,
    GET_POLICY,
    POLICY_GET_DESC,
    SMACK_INSTALL_RULES,
    SMACK_UNINSTALL_RULES,
    SMACK_APPLY_PRIVATE_SHARING_RULES,
    SMACK_DROP_PRIVATE_SHARING_RULES
};

} // namespace SecurityManager

using namespace SecurityManager;

struct policy_entry : ISerializable {
    std::string user;           // uid converted to string
    std::string appId;          // application identifier
    std::string privilege;      // Cynara privilege
    std::string currentLevel;   // current level of privielege, or level asked to be set in privacy manager bucket
    std::string maxLevel;       // holds read maximum policy status or status to be set in admin bucket

    policy_entry() : user(std::to_string(getuid())),
                    appId(SECURITY_MANAGER_ANY),
                    privilege(SECURITY_MANAGER_ANY),
                    currentLevel(""),
                    maxLevel("")
    {}

    policy_entry(IStream &stream) {
        Deserialization::Deserialize(stream, user);
        Deserialization::Deserialize(stream, appId);
        Deserialization::Deserialize(stream, privilege);
        Deserialization::Deserialize(stream, currentLevel);
        Deserialization::Deserialize(stream, maxLevel);
    }

    virtual void Serialize(IStream &stream) const {
        Serialization::Serialize(stream,
            user, appId, privilege, currentLevel, maxLevel);
    }

};
typedef struct policy_entry policy_entry;


struct policy_update_req {
    std::vector<const policy_entry *> units;
};


#endif // _SECURITY_MANAGER_PROTOCOLS_
