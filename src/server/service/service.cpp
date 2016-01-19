/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        service.cpp
 * @author      Michal Witanowski <m.witanowski@samsung.com>
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of security-manager service.
 */

#include <sys/socket.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <sys/smack.h>

#include "connection.h"
#include "protocols.h"
#include "service.h"
#include "service_impl.h"
#include "master-req.h"

namespace SecurityManager {

const InterfaceID IFACE = 1;

Service::Service(const bool isSlave):
        m_isSlave(isSlave)
{
}

GenericSocketService::ServiceDescriptionVector Service::GetServiceDescription()
{
    if (m_isSlave)
        return ServiceDescriptionVector {
            {SLAVE_SERVICE_SOCKET,  /* path */
             "*",   /* smackLabel label (not used, we rely on systemd) */
             IFACE, /* InterfaceID */
             false, /* useSendMsg */
             true}, /* systemdOnly */
        };
    else
        return ServiceDescriptionVector {
            {SERVICE_SOCKET,  /* path */
             "*",   /* smackLabel label (not used, we rely on systemd) */
             IFACE, /* InterfaceID */
             false, /* useSendMsg */
             true}, /* systemdOnly */
        };
}

bool Service::processOne(const ConnectionID &conn, MessageBuffer &buffer,
                                  InterfaceID interfaceID)
{
    LogDebug("Iteration begin. Interface = " << interfaceID);

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    MessageBuffer send;
    bool retval = false;

    uid_t uid;
    pid_t pid;
    std::string smackLabel;

    if (!getPeerID(conn.sock, uid, pid, smackLabel)) {
        LogError("Closing socket because of error: unable to get peer's uid, pid or smack label");
        m_serviceManager->Close(conn);
        return false;
    }

    if (IFACE == interfaceID) {
        Try {
            // deserialize API call type
            int call_type_int;
            Deserialization::Deserialize(buffer, call_type_int);
            SecurityModuleCall call_type = static_cast<SecurityModuleCall>(call_type_int);

            switch (call_type) {
                case SecurityModuleCall::NOOP:
                    LogDebug("call_type: SecurityModuleCall::NOOP");
                    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
                    break;
                case SecurityModuleCall::APP_INSTALL:
                    LogDebug("call_type: SecurityModuleCall::APP_INSTALL");
                    processAppInstall(buffer, send, uid);
                    break;
                case SecurityModuleCall::APP_UNINSTALL:
                    LogDebug("call_type: SecurityModuleCall::APP_UNINSTALL");
                    processAppUninstall(buffer, send, uid);
                    break;
                case SecurityModuleCall::APP_GET_PKGID:
                    processGetPkgId(buffer, send);
                    break;
                case SecurityModuleCall::APP_GET_GROUPS:
                    processGetAppGroups(buffer, send, uid, pid);
                    break;
                case SecurityModuleCall::USER_ADD:
                    processUserAdd(buffer, send, uid);
                    break;
                case SecurityModuleCall::USER_DELETE:
                    processUserDelete(buffer, send, uid);
                    break;
                case SecurityModuleCall::POLICY_UPDATE:
                    processPolicyUpdate(buffer, send, uid, pid, smackLabel);
                    break;
                case SecurityModuleCall::GET_CONF_POLICY_ADMIN:
                    processGetConfiguredPolicy(buffer, send, uid, pid, smackLabel, true);
                    break;
                case SecurityModuleCall::GET_CONF_POLICY_SELF:
                    processGetConfiguredPolicy(buffer, send, uid, pid, smackLabel, false);
                    break;
                case SecurityModuleCall::GET_POLICY:
                    processGetPolicy(buffer, send, uid, pid, smackLabel);
                    break;
                case SecurityModuleCall::POLICY_GET_DESCRIPTIONS:
                    processPolicyGetDesc(send);
                    break;
                case SecurityModuleCall::GET_PRIVILEGES_MAPPING:
                    processPrivilegesMappings(buffer, send);
                    break;
                case SecurityModuleCall::GROUPS_GET:
                    processGroupsGet(send);
                    break;
                case SecurityModuleCall::APP_HAS_PRIVILEGE:
                    processAppHasPrivilege(buffer, send);
                    break;
                default:
                    LogError("Invalid call: " << call_type_int);
                    Throw(ServiceException::InvalidAction);
            }
            // if we reach this point, the protocol is OK
            retval = true;
        } Catch (MessageBuffer::Exception::Base) {
            LogError("Broken protocol.");
        } Catch (ServiceException::Base) {
            LogError("Broken protocol.");
        } catch (const std::exception &e) {
            LogError("STD exception " << e.what());
        } catch (...) {
            LogError("Unknown exception");
        }
    }
    else {
        LogError("Wrong interface");
    }

    if (retval) {
        //send response
        m_serviceManager->Write(conn, send.Pop());
    } else {
        LogError("Closing socket because of error");
        m_serviceManager->Close(conn);
    }

    return retval;
}

void Service::processAppInstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    app_inst_req req;

    Deserialization::Deserialize(buffer, req.appId);
    Deserialization::Deserialize(buffer, req.pkgId);
    Deserialization::Deserialize(buffer, req.privileges);
    Deserialization::Deserialize(buffer, req.appPaths);
    Deserialization::Deserialize(buffer, req.uid);
    Serialization::Serialize(send, serviceImpl.appInstall(req, uid, m_isSlave));
}

void Service::processAppUninstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    std::string appId;

    Deserialization::Deserialize(buffer, appId);
    Serialization::Serialize(send, serviceImpl.appUninstall(appId, uid, m_isSlave));
}

void Service::processGetPkgId(MessageBuffer &buffer, MessageBuffer &send)
{
    std::string appId;
    std::string pkgId;
    int ret;

    Deserialization::Deserialize(buffer, appId);
    ret = serviceImpl.getPkgId(appId, pkgId);
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Serialization::Serialize(send, pkgId);
}

void Service::processGetAppGroups(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid)
{
    std::string appId;
    std::unordered_set<gid_t> gids;
    int ret;

    Deserialization::Deserialize(buffer, appId);
    ret = serviceImpl.getAppGroups(appId, uid, pid, m_isSlave, gids);
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_API_SUCCESS) {
        Serialization::Serialize(send, static_cast<int>(gids.size()));
        for (const auto &gid : gids) {
            Serialization::Serialize(send, gid);
        }
    }
}

void Service::processUserAdd(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    int ret;
    uid_t uidAdded;
    int userType;

    Deserialization::Deserialize(buffer, uidAdded);
    Deserialization::Deserialize(buffer, userType);

    ret = serviceImpl.userAdd(uidAdded, userType, uid, m_isSlave);
    Serialization::Serialize(send, ret);
}

void Service::processUserDelete(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    int ret;
    uid_t uidRemoved;

    Deserialization::Deserialize(buffer, uidRemoved);

    ret = serviceImpl.userDelete(uidRemoved, uid, m_isSlave);
    Serialization::Serialize(send, ret);
}

void Service::processPolicyUpdate(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid, const std::string &smackLabel)
{
    int ret;
    std::vector<policy_entry> policyEntries;

    Deserialization::Deserialize(buffer, policyEntries);

    if (m_isSlave) {
        ret = MasterReq::PolicyUpdate(policyEntries, uid, pid, smackLabel);
    } else {
        ret = serviceImpl.policyUpdate(policyEntries, uid, pid, smackLabel);
    }
    Serialization::Serialize(send, ret);
}

void Service::processGetConfiguredPolicy(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid, const std::string &smackLabel, bool forAdmin)
{
    int ret;
    policy_entry filter;
    Deserialization::Deserialize(buffer, filter);
    std::vector<policy_entry> policyEntries;

    if (m_isSlave) {
        ret = MasterReq::GetConfiguredPolicy(forAdmin, filter, uid, pid, smackLabel, policyEntries);
    } else {
        ret = serviceImpl.getConfiguredPolicy(forAdmin, filter, uid, pid, smackLabel,
                                               policyEntries);
    }

    Serialization::Serialize(send, ret);
    Serialization::Serialize(send, static_cast<int>(policyEntries.size()));
    for (const auto &policyEntry : policyEntries) {
        Serialization::Serialize(send, policyEntry);
    };
}

void Service::processGetPolicy(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid, const std::string &smackLabel)
{
    int ret;
    policy_entry filter;
    Deserialization::Deserialize(buffer, filter);
    std::vector<policy_entry> policyEntries;

    if (m_isSlave) {
        ret = MasterReq::GetPolicy(filter, uid, pid, smackLabel, policyEntries);
    } else {
        ret = serviceImpl.getPolicy(filter, uid, pid, smackLabel, policyEntries);
    }

    Serialization::Serialize(send, ret);
    Serialization::Serialize(send, static_cast<int>(policyEntries.size()));
    for (const auto &policyEntry : policyEntries) {
        Serialization::Serialize(send, policyEntry);
    };
}

void Service::processPolicyGetDesc(MessageBuffer &send)
{
    int ret;
    std::vector<std::string> descriptions;

    if (m_isSlave) {
        ret = MasterReq::PolicyGetDesc(descriptions);
    } else {
        ret = serviceImpl.policyGetDesc(descriptions);
    }
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_API_SUCCESS) {
        Serialization::Serialize(send, static_cast<int>(descriptions.size()));

        for(std::vector<std::string>::size_type i = 0; i != descriptions.size(); i++) {
            Serialization::Serialize(send, descriptions[i]);
        }
    }
}

void Service::processPrivilegesMappings(MessageBuffer &recv, MessageBuffer &send)
{
    std::vector<std::string> privileges;
    std::string version_from, version_to;
    Deserialization::Deserialize(recv, version_from);
    Deserialization::Deserialize(recv, version_to);
    Deserialization::Deserialize(recv, privileges);

    std::vector<std::string> mappings;
    int ret = serviceImpl.getPrivilegesMappings(version_from, version_to, privileges, mappings);

    Serialization::Serialize(send, ret);
    Serialization::Serialize(send, mappings);
}

void Service::processGroupsGet(MessageBuffer &send)
{
    std::vector<std::string> groups;
    int ret = serviceImpl.policyGetGroups(groups);

    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_API_SUCCESS) {
        Serialization::Serialize(send, groups);
    }
}

void Service::processAppHasPrivilege(MessageBuffer &recv, MessageBuffer &send)
{
    std::string appId;
    std::string privilege;
    uid_t uid;

    Deserialization::Deserialize(recv, appId);
    Deserialization::Deserialize(recv, privilege);
    Deserialization::Deserialize(recv, uid);

    bool result;
    int ret = serviceImpl.appHasPrivilege(appId, privilege, uid, m_isSlave, result);

    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Serialization::Serialize(send, static_cast<int>(result));
}

} // namespace SecurityManager
