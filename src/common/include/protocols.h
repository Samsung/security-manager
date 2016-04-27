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
#include <security-manager-types.h>

typedef std::vector<std::pair<std::string, int>> pkg_paths;

struct app_inst_req {
    std::string appName;
    std::string pkgName;
    std::vector<std::string> privileges;
    pkg_paths pkgPaths;
    uid_t uid;
    std::string tizenVersion;
    std::string authorName;
    int installationType = SM_APP_INSTALL_NONE;
};

struct user_req {
    uid_t uid;
    int utype;
};

struct private_sharing_req {
    std::string ownerAppName;
    std::string targetAppName;
    std::vector<std::string> paths;
};

struct path_req {
    std::string pkgName;
    uid_t uid;
    pkg_paths pkgPaths;
    int installationType = SM_APP_INSTALL_NONE;
};

namespace SecurityManager {

extern char const * const SERVICE_SOCKET;

enum class SecurityModuleCall
{
    APP_INSTALL,
    APP_UNINSTALL,
    APP_GET_PKG_NAME,
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
    GROUPS_GET,
    APP_HAS_PRIVILEGE,
    NOOP = 0x90,
};

} // namespace SecurityManager

using namespace SecurityManager;

struct policy_entry : ISerializable {
    std::string user;           // uid converted to string
    std::string appName;        // application identifier
    std::string privilege;      // Cynara privilege
    std::string currentLevel;   // current level of privielege, or level asked to be set in privacy manager bucket
    std::string maxLevel;       // holds read maximum policy status or status to be set in admin bucket

    policy_entry() : user(std::to_string(getuid())),
                    appName(SECURITY_MANAGER_ANY),
                    privilege(SECURITY_MANAGER_ANY),
                    currentLevel(""),
                    maxLevel("")
    {}

    policy_entry(IStream &stream) {
        Deserialization::Deserialize(stream, user);
        Deserialization::Deserialize(stream, appName);
        Deserialization::Deserialize(stream, privilege);
        Deserialization::Deserialize(stream, currentLevel);
        Deserialization::Deserialize(stream, maxLevel);
    }

    virtual void Serialize(IStream &stream) const {
        Serialization::Serialize(stream,
            user, appName, privilege, currentLevel, maxLevel);
    }

};
typedef struct policy_entry policy_entry;


struct policy_update_req {
    std::vector<const policy_entry *> units;
};


#endif // _SECURITY_MANAGER_PROTOCOLS_
