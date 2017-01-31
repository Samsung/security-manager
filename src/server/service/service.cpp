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

namespace SecurityManager {

const InterfaceID IFACE = 1;

Service::Service(){}

GenericSocketService::ServiceDescriptionVector Service::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET,  /* path */
        "*",   /* smackLabel label (not used, we rely on systemd) */
        IFACE, /* InterfaceID */
        false, /* useSendMsg */
        false}, /* systemdOnly */
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

    if (IFACE == interfaceID) {
        Try {
            Credentials creds = Credentials::getCredentialsFromSocket(conn.sock);

            // deserialize API call type
            int call_type_int;
            Deserialization::Deserialize(buffer, call_type_int);
            SecurityModuleCall call_type = static_cast<SecurityModuleCall>(call_type_int);

            switch (call_type) {
                case SecurityModuleCall::NOOP:
                    LogDebug("call_type: SecurityModuleCall::NOOP");
                    Serialization::Serialize(send, static_cast<int>(SECURITY_MANAGER_SUCCESS));
                    break;
                case SecurityModuleCall::APP_INSTALL:
                    LogDebug("call_type: SecurityModuleCall::APP_INSTALL");
                    processAppInstall(buffer, send, creds);
                    break;
                case SecurityModuleCall::APP_UNINSTALL:
                    LogDebug("call_type: SecurityModuleCall::APP_UNINSTALL");
                    processAppUninstall(buffer, send, creds);
                    break;
                case SecurityModuleCall::APP_GET_PKG_NAME:
                    LogDebug("call_type: SecurityModuleCall::APP_GET_PKG_NAME");
                    processGetPkgName(buffer, send);
                    break;
                case SecurityModuleCall::APP_GET_GROUPS:
                    LogDebug("call_type: SecurityModuleCall::APP_GET_GROUPS");
                    processGetAppGroups(buffer, send, creds);
                    break;
                case SecurityModuleCall::USER_ADD:
                    LogDebug("call_type: SecurityModuleCall::USER_ADD");
                    processUserAdd(buffer, send, creds);
                    break;
                case SecurityModuleCall::USER_DELETE:
                    LogDebug("call_type: SecurityModuleCall::USER_DELETE");
                    processUserDelete(buffer, send, creds);
                    break;
                case SecurityModuleCall::POLICY_UPDATE:
                    LogDebug("call_type: SecurityModuleCall::POLICY_UPDATE");
                    processPolicyUpdate(buffer, send, creds);
                    break;
                case SecurityModuleCall::GET_CONF_POLICY_ADMIN:
                    LogDebug("call_type: SecurityModuleCall::GET_CONF_POLICY_ADMIN");
                    processGetConfiguredPolicy(buffer, send, creds, true);
                    break;
                case SecurityModuleCall::GET_CONF_POLICY_SELF:
                    LogDebug("call_type: SecurityModuleCall::GET_CONF_POLICY_SELF");
                    processGetConfiguredPolicy(buffer, send, creds, false);
                    break;
                case SecurityModuleCall::GET_POLICY:
                    LogDebug("call_type: SecurityModuleCall::GET_POLICY");
                    processGetPolicy(buffer, send, creds);
                    break;
                case SecurityModuleCall::POLICY_GET_DESCRIPTIONS:
                    LogDebug("call_type: SecurityModuleCall::POLICY_GET_DESCRIPTIONS");
                    processPolicyGetDesc(send);
                    break;
                case SecurityModuleCall::GROUPS_GET:
                    LogDebug("call_type: SecurityModuleCall::GROUPS_GET");
                    processGroupsGet(send);
                    break;
                case SecurityModuleCall::GROUPS_FOR_UID:
                    processGroupsForUid(buffer, send);
                    break;
                case SecurityModuleCall::APP_HAS_PRIVILEGE:
                    LogDebug("call_type: SecurityModuleCall::APP_HAS_PRIVILEGE");
                    processAppHasPrivilege(buffer, send);
                    break;
                case SecurityModuleCall::APP_APPLY_PRIVATE_SHARING:
                    LogDebug("call_type: SecurityModuleCall::APP_APPLY_PRIVATE_SHARING");
                    processApplyPrivateSharing(buffer, send, creds);
                    break;
                case SecurityModuleCall::APP_DROP_PRIVATE_SHARING:
                    LogDebug("call_type: SecurityModuleCall::APP_DROP_PRIVATE_SHARING");
                    processDropPrivateSharing(buffer, send, creds);
                    break;
                case SecurityModuleCall::PATHS_REGISTER:
                    processPathsRegister(buffer, send, creds);
                    break;
                case SecurityModuleCall::LABEL_FOR_PROCESS:
                    processLabelForProcess(buffer, send);
                    break;
                case SecurityModuleCall::SHM_APP_NAME:
                    processShmAppName(buffer, send, creds);
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

void Service::processAppInstall(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds)
{
    app_inst_req req;

    Deserialization::Deserialize(buffer, req.appName);
    Deserialization::Deserialize(buffer, req.pkgName);
    Deserialization::Deserialize(buffer, req.privileges);
    Deserialization::Deserialize(buffer, req.appDefinedPrivileges);
    Deserialization::Deserialize(buffer, req.pkgPaths);
    Deserialization::Deserialize(buffer, req.uid);
    Deserialization::Deserialize(buffer, req.tizenVersion);
    Deserialization::Deserialize(buffer, req.authorName);
    Deserialization::Deserialize(buffer, req.installationType);
    Deserialization::Deserialize(buffer, req.isHybrid);
    Serialization::Serialize(send, serviceImpl.appInstall(creds, std::move(req)));
}

void Service::processAppUninstall(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds)
{
    app_inst_req req;

    Deserialization::Deserialize(buffer, req.appName);
    Deserialization::Deserialize(buffer, req.pkgName);
    Deserialization::Deserialize(buffer, req.privileges);
    Deserialization::Deserialize(buffer, req.appDefinedPrivileges);
    Deserialization::Deserialize(buffer, req.pkgPaths);
    Deserialization::Deserialize(buffer, req.uid);
    Deserialization::Deserialize(buffer, req.tizenVersion);
    Deserialization::Deserialize(buffer, req.authorName);
    Deserialization::Deserialize(buffer, req.installationType);
    Serialization::Serialize(send, serviceImpl.appUninstall(creds, std::move(req)));
}

void Service::processGetPkgName(MessageBuffer &buffer, MessageBuffer &send)
{
    std::string appName;
    std::string pkgName;
    int ret;

    Deserialization::Deserialize(buffer, appName);
    ret = serviceImpl.getPkgName(appName, pkgName);
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_SUCCESS)
        Serialization::Serialize(send, pkgName);
}

void Service::processGetAppGroups(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds)
{
    std::string appName;
    std::vector<std::string> groups;
    int ret;

    Deserialization::Deserialize(buffer, appName);
    ret = serviceImpl.getAppGroups(creds, appName, groups);
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_SUCCESS)
        Serialization::Serialize(send, groups);
}

void Service::processUserAdd(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds)
{
    int ret;
    uid_t uidAdded;
    int userType;

    Deserialization::Deserialize(buffer, uidAdded);
    Deserialization::Deserialize(buffer, userType);

    ret = serviceImpl.userAdd(creds, uidAdded, userType);
    Serialization::Serialize(send, ret);
}

void Service::processUserDelete(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds)
{
    int ret;
    uid_t uidRemoved;

    Deserialization::Deserialize(buffer, uidRemoved);

    ret = serviceImpl.userDelete(creds, uidRemoved);
    Serialization::Serialize(send, ret);
}

void Service::processPolicyUpdate(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds)
{
    int ret;
    std::vector<policy_entry> policyEntries;

    Deserialization::Deserialize(buffer, policyEntries);

    ret = serviceImpl.policyUpdate(creds, policyEntries);
    Serialization::Serialize(send, ret);
}

void Service::processGetConfiguredPolicy(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds, bool forAdmin)
{
    int ret;
    policy_entry filter;
    Deserialization::Deserialize(buffer, filter);
    std::vector<policy_entry> policyEntries;

    ret = serviceImpl.getConfiguredPolicy(creds, forAdmin, filter, policyEntries);

    Serialization::Serialize(send, ret);
    Serialization::Serialize(send, static_cast<int>(policyEntries.size()));
    for (const auto &policyEntry : policyEntries) {
        Serialization::Serialize(send, policyEntry);
    };
}

void Service::processGetPolicy(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds)
{
    int ret;
    policy_entry filter;
    Deserialization::Deserialize(buffer, filter);
    std::vector<policy_entry> policyEntries;

    ret = serviceImpl.getPolicy(creds, filter, policyEntries);

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

    ret = serviceImpl.policyGetDesc(descriptions);

    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_SUCCESS) {
        Serialization::Serialize(send, static_cast<int>(descriptions.size()));

        for(std::vector<std::string>::size_type i = 0; i != descriptions.size(); i++) {
            Serialization::Serialize(send, descriptions[i]);
        }
    }
}

void Service::processGroupsGet(MessageBuffer &send)
{
    std::vector<std::string> groups;
    int ret = serviceImpl.policyGetGroups(groups);

    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_SUCCESS) {
        Serialization::Serialize(send, groups);
    }
}

void Service::processGroupsForUid(MessageBuffer &recv, MessageBuffer &send)
{
    uid_t uid;
    std::vector<std::string> groups;

    Deserialization::Deserialize(recv, uid);

    int ret = serviceImpl.policyGroupsForUid(uid, groups);

    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_SUCCESS) {
        Serialization::Serialize(send, groups);
    }
}

void Service::processAppHasPrivilege(MessageBuffer &recv, MessageBuffer &send)
{
    std::string appName;
    std::string privilege;
    uid_t uid;

    Deserialization::Deserialize(recv, appName);
    Deserialization::Deserialize(recv, privilege);
    Deserialization::Deserialize(recv, uid);

    bool result;
    int ret = serviceImpl.appHasPrivilege(appName, privilege, uid, result);

    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_SUCCESS)
        Serialization::Serialize(send, static_cast<int>(result));
}

void Service::processApplyPrivateSharing(MessageBuffer &recv, MessageBuffer &send, const Credentials &creds)
{
    std::string ownerAppName, targetAppName;
    std::vector<std::string> paths;
    Deserialization::Deserialize(recv, ownerAppName);
    Deserialization::Deserialize(recv, targetAppName);
    Deserialization::Deserialize(recv, paths);
    int ret = serviceImpl.applyPrivatePathSharing(creds, ownerAppName, targetAppName, paths);
    Serialization::Serialize(send, ret);
}

void Service::processDropPrivateSharing(MessageBuffer &recv, MessageBuffer &send, const Credentials &creds)
{
    std::string ownerAppName, targetAppName;
    std::vector<std::string> paths;
    Deserialization::Deserialize(recv, ownerAppName);
    Deserialization::Deserialize(recv, targetAppName);
    Deserialization::Deserialize(recv, paths);
    int ret = serviceImpl.dropPrivatePathSharing(creds, ownerAppName, targetAppName, paths);
    Serialization::Serialize(send, ret);
}

void Service::processPathsRegister(MessageBuffer &recv, MessageBuffer &send, const Credentials &creds)
{
    path_req req;
    Deserialization::Deserialize(recv, req.pkgName);
    Deserialization::Deserialize(recv, req.uid);
    Deserialization::Deserialize(recv, req.pkgPaths);
    Deserialization::Deserialize(recv, req.installationType);
    int ret = serviceImpl.pathsRegister(creds, std::move(req));
    Serialization::Serialize(send, ret);
}

void Service::processLabelForProcess(MessageBuffer &buffer, MessageBuffer &send)
{
    std::string appName;
    Deserialization::Deserialize(buffer, appName);
    std::string label;
    int ret = serviceImpl.labelForProcess(appName, label);
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_SUCCESS)
        Serialization::Serialize(send, label);
}

void Service::processShmAppName(MessageBuffer &recv, MessageBuffer &send, const Credentials &creds)
{
    std::string shmName, appName;
    Deserialization::Deserialize(recv, shmName, appName);
    int ret = serviceImpl.shmAppName(creds, shmName, appName);
    Serialization::Serialize(send, ret);
}

} // namespace SecurityManager
