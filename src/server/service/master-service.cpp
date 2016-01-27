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
 */
/*
 * @file        master-service.cpp
 * @author      Lukasz Kostyra <l.kostyra@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of security-manager master service.
 */

#include <generic-socket-manager.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include "protocols.h"
#include "zone-utils.h"
#include "cynara.h"
#include "master-service.h"
#include "smack-rules.h"
#include "smack-labels.h"
#include "service_impl.h"

namespace SecurityManager {

const InterfaceID IFACE = 1;

MasterService::MasterService()
{
}

GenericSocketService::ServiceDescriptionVector MasterService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {MASTER_SERVICE_SOCKET, "security-manager-master", IFACE},
    };
}

bool MasterService::processOne(const ConnectionID &conn, MessageBuffer &buffer,
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
        LogError("Closing socket because of error: unable to get peer's uid and pid");
        m_serviceManager->Close(conn);
        return false;
    }

    // FIXME this part needs to be updated when Vasum is added to OBS. See zone-utils.h
    std::string vsmZoneId;
    if (!getZoneIdFromPid(pid, vsmZoneId)) {
        LogError("Failed to extract Zone ID! Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    if (vsmZoneId == ZONE_HOST) {
        LogError("Connection came from host - in master mode this should not happen! Closing.");
        m_serviceManager->Close(conn);
        return false;
    }

    LogInfo("Connection came from Zone " << vsmZoneId);

    if (IFACE == interfaceID) {
        Try {
            // deserialize API call type
            int call_type_int;
            Deserialization::Deserialize(buffer, call_type_int);
            MasterSecurityModuleCall call_type = static_cast<MasterSecurityModuleCall>(call_type_int);

            switch (call_type) {
                case MasterSecurityModuleCall::CYNARA_UPDATE_POLICY:
                    LogDebug("call type MasterSecurityModuleCall::CYNARA_UPDATE_POLICY");
                    processCynaraUpdatePolicy(buffer, send, vsmZoneId);
                    break;
                case MasterSecurityModuleCall::CYNARA_USER_INIT:
                    LogDebug("call type MasterSecurityModuleCall::CYNARA_USER_INIT");
                    processCynaraUserInit(buffer, send);
                    break;
                case MasterSecurityModuleCall::CYNARA_USER_REMOVE:
                    LogDebug("call type MasterSecurityModuleCall::CYNARA_USER_REMOVE");
                    processCynaraUserRemove(buffer, send);
                    break;
                case MasterSecurityModuleCall::POLICY_UPDATE:
                    LogDebug("call type MasterSecurityModuleCall::POLICY_UPDATE");
                    processPolicyUpdate(buffer, send);
                    break;
                case MasterSecurityModuleCall::GET_CONFIGURED_POLICY:
                    LogDebug("call type MasterSecurityModuleCall::GET_CONFIGURED_POLICY");
                    processGetConfiguredPolicy(buffer, send);
                    break;
                case MasterSecurityModuleCall::GET_POLICY:
                    LogDebug("call type MasterSecurityModuleCall::GET_POLICY");
                    processGetPolicy(buffer, send);
                    break;
                case MasterSecurityModuleCall::POLICY_GET_DESC:
                    LogDebug("call type MasterSecurityModuleCall::POLICY_GET_DESC");
                    processPolicyGetDesc(send);
                    break;
                case MasterSecurityModuleCall::SMACK_INSTALL_RULES:
                    LogDebug("call type MasterSecurityModuleCall::SMACK_INSTALL_RULES");
                    processSmackInstallRules(buffer, send, vsmZoneId);
                    break;
                case MasterSecurityModuleCall::SMACK_UNINSTALL_RULES:
                    LogDebug("call type MasterSecurityModuleCall::SMACK_UNINSTALL_RULES");
                    processSmackUninstallRules(buffer, send, vsmZoneId);
                    break;
                case MasterSecurityModuleCall::SMACK_APPLY_PRIVATE_SHARING_RULES:
                    processSmackApplySharingRules(buffer, send, vsmZoneId);
                    break;
                case MasterSecurityModuleCall::SMACK_DROP_PRIVATE_SHARING_RULES:
                    processSmackDropSharingRules(buffer, send, vsmZoneId);
                    break;
                default:
                    LogError("Invalid call: " << call_type_int);
                    Throw(MasterServiceException::InvalidAction);
            }
            // if we reach this point, the protocol is OK
            retval = true;
        } Catch (MessageBuffer::Exception::Base) {
            LogError("Broken protocol.");
        } Catch (MasterServiceException::Base) {
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

void MasterService::processCynaraUpdatePolicy(MessageBuffer &buffer, MessageBuffer &send,
        const std::string &zoneId)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    std::string appId;
    std::string uidstr;
    std::string appLabel;
    std::vector<std::string> privileges;

    Deserialization::Deserialize(buffer, appId);
    Deserialization::Deserialize(buffer, uidstr);
    Deserialization::Deserialize(buffer, privileges);

    appLabel = zoneSmackLabelGenerate(SmackLabels::generateAppLabel(appId), zoneId);

    try {
        CynaraAdmin::getInstance().UpdateAppPolicy(appLabel, uidstr, privileges);
    } catch (const CynaraException::Base &e) {
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        goto out;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        ret = SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;

out:
    Serialization::Serialize(send, ret);
}

void MasterService::processCynaraUserInit(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
    uid_t uidAdded;
    int userType;

    Deserialization::Deserialize(buffer, uidAdded);
    Deserialization::Deserialize(buffer, userType);

    try {
        CynaraAdmin::getInstance().UserInit(uidAdded,
                                            static_cast<security_manager_user_type>(userType));
    } catch (CynaraException::InvalidParam &e) {
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    Serialization::Serialize(send, ret);
}

void MasterService::processCynaraUserRemove(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
    uid_t uidDeleted;

    Deserialization::Deserialize(buffer, uidDeleted);

    try {
        CynaraAdmin::getInstance().UserRemove(uidDeleted);
    } catch (CynaraException::InvalidParam &e) {
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    Serialization::Serialize(send, ret);
}

void MasterService::processPolicyUpdate(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    std::vector<policy_entry> policyEntries;
    uid_t uid;
    pid_t pid;
    std::string smackLabel;

    Deserialization::Deserialize(buffer, policyEntries);
    Deserialization::Deserialize(buffer, uid);
    Deserialization::Deserialize(buffer, pid);
    Deserialization::Deserialize(buffer, smackLabel);

    ret = serviceImpl.policyUpdate(policyEntries, uid, pid, smackLabel);
    Serialization::Serialize(send, ret);
}

void MasterService::processGetConfiguredPolicy(MessageBuffer &buffer, MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    bool forAdmin;
    policy_entry filter;
    uid_t uid;
    pid_t pid;
    std::string smackLabel;
    std::vector<policy_entry> policyEntries;

    Deserialization::Deserialize(buffer, forAdmin);
    Deserialization::Deserialize(buffer, filter);
    Deserialization::Deserialize(buffer, uid);
    Deserialization::Deserialize(buffer, pid);
    Deserialization::Deserialize(buffer, smackLabel);

    ret = serviceImpl.getConfiguredPolicy(forAdmin, filter, uid, pid, smackLabel, policyEntries);
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Serialization::Serialize(send, policyEntries);
}

void MasterService::processGetPolicy(MessageBuffer &buffer, MessageBuffer &send)
{
    (void) buffer;
    int ret = SECURITY_MANAGER_API_ERROR_BAD_REQUEST;

    // FIXME getPolicy is not ready to work in Master mode. Uncomment below code when getPolicy will
    //       be implemented for Master.
    /*
    policy_entry filter;
    uid_t uid;
    pid_t pid;
    std::string smackLabel;
    std::vector<policy_entry> policyEntries;

    Deserialization::Deserialize(buffer, filter);
    Deserialization::Deserialize(buffer, uid);
    Deserialization::Deserialize(buffer, pid);
    Deserialization::Deserialize(buffer, smackLabel);

    ret = serviceImpl.getPolicy(filter, uid, pid, smackLabel, policyEntries);*/
    Serialization::Serialize(send, ret);
    /*if (ret == SECURITY_MANAGER_API_SUCCESS)
        Serialization::Serialize(send, policyEntries);*/
}

void MasterService::processPolicyGetDesc(MessageBuffer &send)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    std::vector<std::string> descriptions;

    ret = serviceImpl.policyGetDesc(descriptions);
    Serialization::Serialize(send, ret);
    if (ret == SECURITY_MANAGER_API_SUCCESS)
        Serialization::Serialize(send, descriptions);
}

void MasterService::processSmackInstallRules(MessageBuffer &buffer, MessageBuffer &send,
                                             const std::string &zoneId)
{
    int ret = SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    std::string appId, pkgId, authorId;
    std::vector<std::string> pkgContents, appsGranted, accessPackages;

    Deserialization::Deserialize(buffer, appId);
    Deserialization::Deserialize(buffer, pkgId);
    Deserialization::Deserialize(buffer, authorId);
    Deserialization::Deserialize(buffer, pkgContents);
    Deserialization::Deserialize(buffer, appsGranted);
    Deserialization::Deserialize(buffer, accessPackages);

    try {
        LogDebug("Adding Smack rules for new appId: " << appId << " with pkgId: "
                << pkgId << ". Applications in package: " << pkgContents.size()
                << ". Other Tizen 2.X applications: " << appsGranted.size());

        SmackRules::installApplicationRules(appId, pkgId, authorId, pkgContents, appsGranted, accessPackages, zoneId);

        // FIXME implement zoneSmackLabelMap and check if works when Smack Namespaces are implemented
        std::string zoneAppLabel = SmackLabels::generateAppLabel(appId);
        std::string zonePkgLabel = SmackLabels::generatePkgLabel(pkgId);
        std::string hostAppLabel = zoneSmackLabelGenerate(zoneAppLabel, zoneId);
        std::string hostPkgLabel = zoneSmackLabelGenerate(zonePkgLabel, zoneId);

        if (!zoneSmackLabelMap(hostAppLabel, zoneId, zoneAppLabel)) {
            LogError("Failed to apply Smack label mapping for application " << appId);
            goto out;
        }

        if (!zoneSmackLabelMap(hostPkgLabel, zoneId, zonePkgLabel)) {
            LogError("Failed to apply Smack label mapping for package " << pkgId);
            goto out;
        }
    } catch (const SmackException::Base &e) {
        LogError("Error while adding Smack rules for application: " << e.DumpToString());
        ret = SECURITY_MANAGER_API_ERROR_SETTING_FILE_LABEL_FAILED;
        goto out;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        ret =  SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    ret = SECURITY_MANAGER_API_SUCCESS;
out:
    Serialization::Serialize(send, ret);
}

void MasterService::processSmackUninstallRules(MessageBuffer &buffer, MessageBuffer &send,
                                               const std::string &zoneId)
{
    std::string appId, pkgId;
    std::vector<std::string> pkgContents, appsGranted;
    bool removeApp = false;
    bool removePkg = false;

    Deserialization::Deserialize(buffer, appId);
    Deserialization::Deserialize(buffer, pkgId);
    Deserialization::Deserialize(buffer, pkgContents);
    Deserialization::Deserialize(buffer, appsGranted);
    Deserialization::Deserialize(buffer, removeApp);
    Deserialization::Deserialize(buffer, removePkg);

    try {
        if (removeApp) {
            LogDebug("Removing smack rules for deleted appId " << appId);
            SmackRules::uninstallApplicationRules(appId, pkgId, pkgContents, appsGranted, zoneId);

            std::string zoneAppLabel = SmackLabels::generateAppLabel(appId);
            std::string hostAppLabel = zoneSmackLabelGenerate(zoneAppLabel, zoneId);
            // FIXME zoneSmackLabelUnmap should throw exception on error, not return false
            // FIXME implement zoneSmackLabelUnmap and check if works when Smack Namespaces are implemented
            if (!zoneSmackLabelUnmap(hostAppLabel, zoneId)) {
                LogError("Failed to unmap Smack labels for application " << appId);
                Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
                return;
            }
        }

        if (removePkg) {
            LogDebug("Removing Smack rules for deleted pkgId " << pkgId);
            SmackRules::uninstallPackageRules(pkgId);

            std::string zonePkgLabel = SmackLabels::generatePkgLabel(pkgId);
            std::string hostPkgLabel = zoneSmackLabelGenerate(zonePkgLabel, zoneId);
            if (!zoneSmackLabelUnmap(hostPkgLabel, zoneId)) {
                LogError("Failed to unmap Smack label for package " << pkgId);
                Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
                return;
            }
        }
    } catch (const SmackException::Base &e) {
        LogError("Error while removing Smack rules for application: " << e.DumpToString());
        Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SETTING_FILE_LABEL_FAILED);
        return;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY);
        return;
    }

    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
}

void MasterService::processSmackApplySharingRules(MessageBuffer &buffer, MessageBuffer &send,
                                const std::string &zoneId)
{
    std::string ownerPkgId, targetAppId, path;
    std::vector<std::string> pkgContents;
    int ownerTargetCount, pathCount;

    Deserialization::Deserialize(buffer, ownerPkgId);
    Deserialization::Deserialize(buffer, pkgContents);
    Deserialization::Deserialize(buffer, targetAppId);
    Deserialization::Deserialize(buffer, path);
    Deserialization::Deserialize(buffer, ownerTargetCount);
    Deserialization::Deserialize(buffer, pathCount);

    (void)zoneId;

    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
}

void MasterService::processSmackDropSharingRules(MessageBuffer &buffer, MessageBuffer &send,
                                const std::string &zoneId)
{
    std::string ownerPkgId, targetAppId, path;
    std::vector<std::string> pkgContents;
    int ownerTargetCount, pathCount;

    Deserialization::Deserialize(buffer, ownerPkgId);
    Deserialization::Deserialize(buffer, pkgContents);
    Deserialization::Deserialize(buffer, targetAppId);
    Deserialization::Deserialize(buffer, path);
    Deserialization::Deserialize(buffer, ownerTargetCount);
    Deserialization::Deserialize(buffer, pathCount);

    (void)zoneId;

    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
}

} // namespace SecurityManager
