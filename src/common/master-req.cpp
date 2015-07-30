/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        master-req.cpp
 * @author      Lukasz Kostyra <l.kostyra@samsung.com>
 * @brief       Definitions of master request calls
 */

#include "master-req.h"

#include <dpl/serialization.h>

#include "message-buffer.h"
#include "connection.h"

namespace SecurityManager {
namespace MasterReq {

int CynaraPolicyUpdate(const std::string &appId,  const std::string &uidstr,
                       const std::vector<std::string> &oldPkgPrivileges,
                       const std::vector<std::string> &newPkgPrivileges)
{
    int ret;
    MessageBuffer sendBuf, retBuf;

    Serialization::Serialize(sendBuf,
        static_cast<int>(MasterSecurityModuleCall::CYNARA_UPDATE_POLICY),
        appId, uidstr, oldPkgPrivileges, newPkgPrivileges);

    ret = sendToServer(MASTER_SERVICE_SOCKET, sendBuf.Pop(), retBuf);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Deserialization::Deserialize(retBuf, ret);

    return ret;
}

int CynaraUserInit(const uid_t uidAdded, int userType)
{
    int ret;
    MessageBuffer sendBuf, retBuf;

    Serialization::Serialize(sendBuf,
        static_cast<int>(MasterSecurityModuleCall::CYNARA_USER_INIT),
        uidAdded, userType);

    ret = sendToServer(MASTER_SERVICE_SOCKET, sendBuf.Pop(), retBuf);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Deserialization::Deserialize(retBuf, ret);

    return ret;
}

int CynaraUserRemove(const uid_t uidDeleted)
{
    int ret;
    MessageBuffer sendBuf, retBuf;

    Serialization::Serialize(sendBuf,
        static_cast<int>(MasterSecurityModuleCall::CYNARA_USER_REMOVE),
        uidDeleted);

    ret = sendToServer(MASTER_SERVICE_SOCKET, sendBuf.Pop(), retBuf);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Deserialization::Deserialize(retBuf, ret);

    return ret;
}

int SmackInstallRules(const std::string &appId, const std::string &pkgId,
                      const std::vector<std::string> &pkgContents)
{
    int ret;
    MessageBuffer sendBuf, retBuf;
    Serialization::Serialize(sendBuf,
        static_cast<int>(MasterSecurityModuleCall::SMACK_INSTALL_RULES),
        appId, pkgId, pkgContents);

    ret = sendToServer(MASTER_SERVICE_SOCKET, sendBuf.Pop(), retBuf);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Deserialization::Deserialize(retBuf, ret);

    return ret;
}

int SmackUninstallRules(const std::string &appId, const std::string &pkgId,
                        const std::vector<std::string> &pkgContents, const bool removePkg)
{
    int ret;
    MessageBuffer sendBuf, retBuf;

    Serialization::Serialize(sendBuf,
        static_cast<int>(MasterSecurityModuleCall::SMACK_UNINSTALL_RULES),
        appId, pkgId, pkgContents, removePkg);

    ret = sendToServer(MASTER_SERVICE_SOCKET, sendBuf.Pop(), retBuf);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Deserialization::Deserialize(retBuf, ret);

    return ret;
}

// Following three requests are just forwarded security-manager API calls
// these do not access Privilege DB, so all can be forwarded to Master
int PolicyUpdate(const std::vector<policy_entry> &policyEntries, uid_t uid, pid_t pid,
                              const std::string &smackLabel)
{
    int ret;
    MessageBuffer sendBuf, retBuf;

    Serialization::Serialize(sendBuf,
        static_cast<int>(MasterSecurityModuleCall::POLICY_UPDATE),
        policyEntries, uid, pid, smackLabel);

    ret = sendToServer(MASTER_SERVICE_SOCKET, sendBuf.Pop(), retBuf);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Deserialization::Deserialize(retBuf, ret);

    return ret;
}

int GetConfiguredPolicy(bool forAdmin, const policy_entry &filter, uid_t uid, pid_t pid,
                        const std::string &smackLabel, std::vector<policy_entry> &policyEntries)
{
    int ret;
    MessageBuffer sendBuf, retBuf;

    Serialization::Serialize(sendBuf,
        static_cast<int>(MasterSecurityModuleCall::GET_CONFIGURED_POLICY),
        forAdmin, filter, uid, pid, smackLabel);

    ret = sendToServer(MASTER_SERVICE_SOCKET, sendBuf.Pop(), retBuf);
    if (ret == SECURITY_MANAGER_API_SUCCESS) {
        Deserialization::Deserialize(retBuf, ret);
        if (ret == SECURITY_MANAGER_API_SUCCESS)
            Deserialization::Deserialize(retBuf, policyEntries);
    }

    return ret;
}

int GetPolicy(const policy_entry &filter, uid_t uid, pid_t pid, const std::string &smackLabel,
              std::vector<policy_entry> &policyEntries)
{
    int ret;
    MessageBuffer sendBuf, retBuf;

    Serialization::Serialize(sendBuf,
        static_cast<int>(MasterSecurityModuleCall::GET_POLICY),
        filter, uid, pid, smackLabel);

    ret = sendToServer(MASTER_SERVICE_SOCKET, sendBuf.Pop(), retBuf);
    if (ret == SECURITY_MANAGER_API_SUCCESS) {
        Deserialization::Deserialize(retBuf, ret);
        if (ret == SECURITY_MANAGER_API_SUCCESS)
            Deserialization::Deserialize(retBuf, policyEntries);
    }

    return ret;
}

int PolicyGetDesc(std::vector<std::string> &descriptions)
{
    int ret;
    MessageBuffer sendBuf, retBuf;

    Serialization::Serialize(sendBuf,
        static_cast<int>(MasterSecurityModuleCall::POLICY_GET_DESC));

    ret = sendToServer(MASTER_SERVICE_SOCKET, sendBuf.Pop(), retBuf);
    if (ret == SECURITY_MANAGER_API_SUCCESS) {
        Deserialization::Deserialize(retBuf, ret);
        if (ret == SECURITY_MANAGER_API_SUCCESS)
            Deserialization::Deserialize(retBuf, descriptions);
    }

    return ret;
}

} // namespace MasterReq
} // namespace SecurityManager
