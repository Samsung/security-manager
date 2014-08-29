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
 * @file        service.cpp
 * @author      Michal Witanowski <m.witanowski@samsung.com>
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of security-manager service.
 */

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <pwd.h>
#include <limits.h>
#include <cstring>

#include "service.h"
#include "protocols.h"
#include "security-manager.h"
#include "smack-common.h"
#include "smack-rules.h"
#include "smack-labels.h"
#include "privilege_db.h"
#include "cynara.h"

namespace SecurityManager {

const InterfaceID IFACE = 1;


Service::Service()
{
}

GenericSocketService::ServiceDescriptionVector Service::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET, "security-manager", IFACE},
    };
}

void Service::accept(const AcceptEvent &event)
{
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock <<
             " ConnectionID.counter: " << event.connectionID.counter <<
             " ServiceID: " << event.interfaceID);

    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void Service::write(const WriteEvent &event)
{
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
             " Size: " << event.size <<
             " Left: " << event.left);

    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void Service::process(const ReadEvent &event)
{
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while (processOne(event.connectionID, info.buffer, info.interfaceID));
}

void Service::close(const CloseEvent &event)
{
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

static bool getPeerUserID(int sock, uid_t *uid) {
    struct ucred cr;
    socklen_t len = sizeof (cr);
    if (!uid) {
        return false;
    }
    if (!getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cr, &len)) {
        *uid = cr.uid;
        return true;
    }
    return false;
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

    if(!getPeerUserID(conn.sock, &uid)) {
        LogError("Closing socket because of error: unable to get peer's uid");
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
        } catch (std::exception &e) {
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

static inline bool isSubDir(const char *parent, const char *subdir)
{
    while (*parent && *subdir)
        if (*parent++ != *subdir++)
            return false;

    return (*subdir == '/');
}

static inline bool installRequestAuthCheck(const app_inst_req &req, uid_t uid)
{
    if (uid == 0)
        return true;

    struct passwd *pwd;
    do {
        errno = 0;
        pwd = getpwuid(uid);
        if (!pwd && errno != EINTR) {
            LogError("getpwuid failed with '" << uid
                    << "' as paramter: " << strerror(errno));
            return false;
        }
    } while (!pwd);

    std::unique_ptr<char, std::function<void(void*)>> home(
        realpath(pwd->pw_dir, NULL), free);
    if (!home.get()) {
            LogError("realpath failed with '" << pwd->pw_dir
                    << "' as paramter: " << strerror(errno));
            return false;
    }

    for (const auto &appPath : req.appPaths) {
        std::unique_ptr<char, std::function<void(void*)>> real_path(
            realpath(appPath.first.c_str(), NULL), free);
        if (!real_path.get()) {
            LogError("realpath failed with '" << appPath.first.c_str()
                    << "' as paramter: " << strerror(errno));
            return false;
        }
        LogDebug("Requested path is '" << appPath.first.c_str()
                << "'. User's HOME is '" << pwd->pw_dir << "'");
        if (!isSubDir(home.get(), real_path.get())) {
            LogWarning("User's apps may have registered folders only in user's home dir");
            return false;
        }

        app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
        if (pathType == SECURITY_MANAGER_PATH_PUBLIC) {
            LogWarning("Only root can register SECURITY_MANAGER_PATH_PUBLIC path");
            return false;
        }
    }
    return true;
}

bool Service::processAppInstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    bool pkgIdIsNew = false;
    std::vector<std::string> addedPermissions;
    std::vector<std::string> removedPermissions;

    // deserialize request data
    app_inst_req req;
    Deserialization::Deserialize(buffer, req.appId);
    Deserialization::Deserialize(buffer, req.pkgId);
    Deserialization::Deserialize(buffer, req.privileges);
    Deserialization::Deserialize(buffer, req.appPaths);

    if(!installRequestAuthCheck(req, uid)) {
        LogError("Request from uid " << uid << " for app installation denied");
        Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED);
        return false;
    }

    std::string smackLabel;
    if (!generateAppLabel(req.pkgId, smackLabel)) {
        LogError("Cannot generate Smack label for package: " << req.pkgId);
        Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
        return false;
    }

    LogDebug("Install parameters: appId: " << req.appId << ", pkgId: " << req.pkgId
            << ", generated smack label: " << smackLabel);

    // create null terminated array of strings for permissions
    std::unique_ptr<const char *[]> pp_permissions(new const char* [req.privileges.size() + 1]);
    for (size_t i = 0; i < req.privileges.size(); ++i) {
        LogDebug("  Permission = " << req.privileges[i]);
        pp_permissions[i] = req.privileges[i].c_str();
    }
    pp_permissions[req.privileges.size()] = nullptr;

    try {
        std::vector<std::string> oldPkgPrivileges, newPkgPrivileges;
        std::string uidstr = uid ? std::to_string(static_cast<unsigned int>(uid))
                             : CYNARA_ADMIN_WILDCARD;

        LogDebug("Install parameters: appId: " << req.appId << ", pkgId: " << req.pkgId
                 << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

        m_privilegeDb.BeginTransaction();
        m_privilegeDb.GetPkgPrivileges(req.pkgId, uid, oldPkgPrivileges);
        m_privilegeDb.AddApplication(req.appId, req.pkgId, uid, pkgIdIsNew);
        m_privilegeDb.UpdateAppPrivileges(req.appId, uid, req.privileges);
        m_privilegeDb.GetPkgPrivileges(req.pkgId, uid, newPkgPrivileges);
        CynaraAdmin::UpdatePackagePolicy(req.pkgId, uidstr, oldPkgPrivileges,
                                         newPkgPrivileges);
        m_privilegeDb.CommitTransaction();
        LogDebug("Application installation commited to database");
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        m_privilegeDb.RollbackTransaction();
        LogError("Error while saving application info to database: " << e.DumpToString());
        goto error_label;
    } catch (const CynaraException::Base &e) {
        m_privilegeDb.RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        goto error_label;
    } catch (const std::bad_alloc &e) {
        m_privilegeDb.RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        goto error_label;
    }

    // register paths
    for (const auto &appPath : req.appPaths) {
        const std::string &path = appPath.first;
        app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
        int result = setupPath(req.pkgId, path, pathType);

        if (!result) {
            LogError("setupPath() failed");
            goto error_label;
        }
    }

    if (pkgIdIsNew) {
        LogDebug("Adding Smack rules for new pkgId " << req.pkgId);
        if (!SmackRules::installPackageRules(req.pkgId)) {
            LogError("Failed to apply package-specific smack rules");
            goto error_label;
        }
    }

    // success
    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
    return true;

error_label:
    Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
    return false;
}

bool Service::processAppUninstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid)
{
    // deserialize request data
    std::string appId;
    std::string pkgId;
    std::string smackLabel;
    bool appExists = true;
    bool removePkg = false;

    Deserialization::Deserialize(buffer, appId);

    try {
        std::vector<std::string> oldPkgPrivileges, newPkgPrivileges;

        m_privilegeDb.BeginTransaction();
        if (!m_privilegeDb.GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId <<
                " not found in database while uninstalling");
            m_privilegeDb.RollbackTransaction();
            appExists = false;
        } else {
            if (!generateAppLabel(pkgId, smackLabel)) {
                LogError("Cannot generate Smack label for package: " << pkgId);
                goto error_label;

            }

            std::string uidstr = uid ? std::to_string(static_cast<unsigned int>(uid))
                                 : CYNARA_ADMIN_WILDCARD;

            LogDebug("Uninstall parameters: appId: " << appId << ", pkgId: " << pkgId
                     << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

            m_privilegeDb.GetPkgPrivileges(pkgId, uid, oldPkgPrivileges);
            m_privilegeDb.UpdateAppPrivileges(appId, uid, std::vector<std::string>());
            m_privilegeDb.RemoveApplication(appId, uid, removePkg);
            m_privilegeDb.GetPkgPrivileges(pkgId, uid, newPkgPrivileges);
            CynaraAdmin::UpdatePackagePolicy(pkgId, uidstr, oldPkgPrivileges,
                                             newPkgPrivileges);
            m_privilegeDb.CommitTransaction();
            LogDebug("Application uninstallation commited to database");
        }
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        m_privilegeDb.RollbackTransaction();
        LogError("Error while removing application info from database: " << e.DumpToString());
        goto error_label;
    } catch (const CynaraException::Base &e) {
        m_privilegeDb.RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        goto error_label;
    } catch (const std::bad_alloc &e) {
        m_privilegeDb.RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        goto error_label;
    }

    if (appExists) {

        if (removePkg) {
            LogDebug("Removing Smack rules for deleted pkgId " << pkgId);
            if (!SmackRules::uninstallPackageRules(pkgId)) {
                LogError("Error on uninstallation of package-specific smack rules");
                goto error_label;
            }
        }
    }

    // success
    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
    return true;

error_label:
    Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
    return false;
}

bool Service::processGetPkgId(MessageBuffer &buffer, MessageBuffer &send)
{
    // deserialize request data
    std::string appId;
    std::string pkgId;

    Deserialization::Deserialize(buffer, appId);
    LogDebug("appId: " << appId);

    try {
        if (!m_privilegeDb.GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId << " not found in database");
            Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT);
            return false;
        } else {
            LogDebug("pkgId: " << pkgId);
        }
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        LogError("Error while getting pkgId from database: " << e.DumpToString());
        Serialization::Serialize(send, SECURITY_MANAGER_API_ERROR_SERVER_ERROR);
        return false;
    }

     // success
    Serialization::Serialize(send, SECURITY_MANAGER_API_SUCCESS);
    Serialization::Serialize(send, pkgId);
    return true;
}

} // namespace SecurityManager
