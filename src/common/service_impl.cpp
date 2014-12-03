/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        service_impl.cpp
 * @author      Michal Witanowski <m.witanowski@samsung.com>
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of the service methods
 */

#include <grp.h>
#include <limits.h>
#include <pwd.h>

#include <cstring>
#include <algorithm>

#include <dpl/log/log.h>
#include <tzplatform_config.h>

#include "protocols.h"
#include "privilege_db.h"
#include "cynara.h"
#include "smack-common.h"
#include "smack-rules.h"
#include "smack-labels.h"

#include "service_impl.h"

namespace SecurityManager {
namespace ServiceImpl {

static uid_t getGlobalUserId(void)
{
    static uid_t globaluid = tzplatform_getuid(TZ_SYS_GLOBALAPP_USER);
    return globaluid;
}

/**
 * Unifies user data of apps installed for all users
 * @param  uid            peer's uid - may be changed during process
 * @param  cynaraUserStr  string to which cynara user parameter will be put
 */
static void checkGlobalUser(uid_t &uid, std::string &cynaraUserStr)
{
    static uid_t globaluid = getGlobalUserId();
    if (uid == 0 || uid == globaluid) {
        uid = globaluid;
        cynaraUserStr = CYNARA_ADMIN_WILDCARD;
    } else {
        cynaraUserStr = std::to_string(static_cast<unsigned int>(uid));
    }
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
    struct passwd *pwd;
    do {
        errno = 0;
        pwd = getpwuid(uid);
        if (!pwd && errno != EINTR) {
            LogError("getpwuid failed with '" << uid
                    << "' as parameter: " << strerror(errno));
            return false;
        }
    } while (!pwd);

    std::unique_ptr<char, std::function<void(void*)>> home(
        realpath(pwd->pw_dir, NULL), free);
    if (!home.get()) {
            LogError("realpath failed with '" << pwd->pw_dir
                    << "' as parameter: " << strerror(errno));
            return false;
    }

    for (const auto &appPath : req.appPaths) {
        std::unique_ptr<char, std::function<void(void*)>> real_path(
            realpath(appPath.first.c_str(), NULL), free);
        if (!real_path.get()) {
            LogError("realpath failed with '" << appPath.first.c_str()
                    << "' as parameter: " << strerror(errno));
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

int appInstall(const app_inst_req &req, uid_t uid)
{
    bool pkgIdIsNew = false;
    std::vector<std::string> addedPermissions;
    std::vector<std::string> removedPermissions;

    std::string uidstr;
    if (uid) {
        if (uid != req.uid) {
            LogError("User " << uid <<
                     " is denied to install application for user " << req.uid);
            return SECURITY_MANAGER_API_ERROR_ACCESS_DENIED;
        }
    } else {
        if (req.uid)
            uid = req.uid;
    }
    checkGlobalUser(uid, uidstr);

    if (!installRequestAuthCheck(req, uid)) {
        LogError("Request from uid " << uid << " for app installation denied");
        return SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED;
    }

    std::string smackLabel;
    if (!generateAppLabel(req.pkgId, smackLabel)) {
        LogError("Cannot generate Smack label for package: " << req.pkgId);
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
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

        LogDebug("Install parameters: appId: " << req.appId << ", pkgId: " << req.pkgId
                 << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

        PrivilegeDb::getInstance().BeginTransaction();

        std::string pkg;
        bool ret = PrivilegeDb::getInstance().GetAppPkgId(req.appId, pkg);
        if (ret == true && pkg != req.pkgId) {
            LogError("Application already installed with different package id");
            PrivilegeDb::getInstance().RollbackTransaction();
            return SECURITY_MANAGER_API_ERROR_INPUT_PARAM;
        }
        PrivilegeDb::getInstance().GetPkgPrivileges(req.pkgId, uid, oldPkgPrivileges);
        PrivilegeDb::getInstance().AddApplication(req.appId, req.pkgId, uid, pkgIdIsNew);
        PrivilegeDb::getInstance().UpdateAppPrivileges(req.appId, uid, req.privileges);
        PrivilegeDb::getInstance().GetPkgPrivileges(req.pkgId, uid, newPkgPrivileges);
        CynaraAdmin::UpdatePackagePolicy(smackLabel, uidstr, oldPkgPrivileges,
                                         newPkgPrivileges);
        PrivilegeDb::getInstance().CommitTransaction();
        LogDebug("Application installation commited to database");
    } catch (const PrivilegeDb::Exception::IOError &e) {
        LogError("Cannot access application database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while saving application info to database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    // register paths
    for (const auto &appPath : req.appPaths) {
        const std::string &path = appPath.first;
        app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
        int result = setupPath(req.pkgId, path, pathType);

        if (!result) {
            LogError("setupPath() failed");
            return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
        }
    }

    if (pkgIdIsNew) {
        LogDebug("Adding Smack rules for new pkgId " << req.pkgId);
        if (!SmackRules::installPackageRules(req.pkgId)) {
            LogError("Failed to apply package-specific smack rules");
            return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
        }
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int appUninstall(const std::string &appId, uid_t uid)
{
    std::string pkgId;
    std::string smackLabel;
    bool appExists = true;
    bool removePkg = false;
    std::string uidstr;
    checkGlobalUser(uid, uidstr);

    try {
        std::vector<std::string> oldPkgPrivileges, newPkgPrivileges;

        PrivilegeDb::getInstance().BeginTransaction();
        if (!PrivilegeDb::getInstance().GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId <<
                " not found in database while uninstalling");
            PrivilegeDb::getInstance().RollbackTransaction();
            appExists = false;
        } else {

            LogDebug("Uninstall parameters: appId: " << appId << ", pkgId: " << pkgId
                     << ", uidstr " << uidstr << ", generated smack label: " << smackLabel);

            if (!generateAppLabel(pkgId, smackLabel)) {
                LogError("Cannot generate Smack label for package: " << pkgId);
                return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
            }

            PrivilegeDb::getInstance().GetPkgPrivileges(pkgId, uid, oldPkgPrivileges);
            PrivilegeDb::getInstance().UpdateAppPrivileges(appId, uid, std::vector<std::string>());
            PrivilegeDb::getInstance().RemoveApplication(appId, uid, removePkg);
            PrivilegeDb::getInstance().GetPkgPrivileges(pkgId, uid, newPkgPrivileges);
            CynaraAdmin::UpdatePackagePolicy(smackLabel, uidstr, oldPkgPrivileges,
                                             newPkgPrivileges);
            PrivilegeDb::getInstance().CommitTransaction();
            LogDebug("Application uninstallation commited to database");
        }
    } catch (const PrivilegeDb::Exception::IOError &e) {
        LogError("Cannot access application database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while removing application info from database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        PrivilegeDb::getInstance().RollbackTransaction();
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    if (appExists) {

        if (removePkg) {
            LogDebug("Removing Smack rules for deleted pkgId " << pkgId);
            if (!SmackRules::uninstallPackageRules(pkgId)) {
                LogError("Error on uninstallation of package-specific smack rules");
                return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
            }
        }
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int getPkgId(const std::string &appId, std::string &pkgId)
{
    LogDebug("appId: " << appId);

    try {
        if (!PrivilegeDb::getInstance().GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId << " not found in database");
            return SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT;
        } else {
            LogDebug("pkgId: " << pkgId);
        }
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting pkgId from database: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

int getAppGroups(const std::string &appId, uid_t uid, pid_t pid, std::unordered_set<gid_t> &gids)
{
    try {
        std::string pkgId;
        std::string smackLabel;
        std::string uidStr = std::to_string(uid);
        std::string pidStr = std::to_string(pid);

        LogDebug("appId: " << appId);

        if (!PrivilegeDb::getInstance().GetAppPkgId(appId, pkgId)) {
            LogWarning("Application " << appId << " not found in database");
            return SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT;
        }
        LogDebug("pkgId: " << pkgId);

        if (!generateAppLabel(pkgId, smackLabel)) {
             LogError("Cannot generate Smack label for package: " << pkgId);
            return SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT;
        }
        LogDebug("smack label: " << smackLabel);

        std::vector<std::string> privileges;
        PrivilegeDb::getInstance().GetPkgPrivileges(pkgId, uid, privileges);
        /*there is also a need of checking, if privilege is granted to all users*/
        size_t tmp = privileges.size();
        PrivilegeDb::getInstance().GetPkgPrivileges(pkgId, getGlobalUserId(), privileges);
        /*privileges needs to be sorted and with no duplications - for cynara sake*/
        std::inplace_merge(privileges.begin(), privileges.begin() + tmp, privileges.end());
        privileges.erase( unique( privileges.begin(), privileges.end() ), privileges.end() );

        for (const auto &privilege : privileges) {
            std::vector<std::string> gidsTmp;
            PrivilegeDb::getInstance().GetPrivilegeGroups(privilege, gidsTmp);
            if (!gidsTmp.empty()) {
                LogDebug("Considering privilege " << privilege << " with " <<
                    gidsTmp.size() << " groups assigned");
                if (Cynara::getInstance().check(smackLabel, privilege, uidStr, pidStr)) {
                    for_each(gidsTmp.begin(), gidsTmp.end(), [&] (std::string group)
                    {
                        struct group *grp = getgrnam(group.c_str());
                        if (grp == NULL) {
                                LogError("No such group: " << group.c_str());
                                return;
                        }
                        gids.insert(grp->gr_gid);
                    });
                    LogDebug("Cynara allowed, adding groups");
                } else
                    LogDebug("Cynara denied, not adding groups");
            }
        }
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Database error: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        return SECURITY_MANAGER_API_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        return SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY;
    }

    return SECURITY_MANAGER_API_SUCCESS;
}

} /* namespace ServiceImpl */
} /* namespace SecurityManager */
