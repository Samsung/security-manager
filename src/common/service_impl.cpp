/*
 *  Copyright (c) 2014-2017 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @author      Krzysztof Sasiak <k.sasiak@samsung.com>
 * @brief       Implementation of the service methods
 */

#include <fcntl.h>
#include <grp.h>
#include <linux/xattr.h>
#include <limits.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <algorithm>

#include <dpl/log/log.h>
#include <dpl/errno_string.h>

#include <sys/smack.h>

#include <config.h>
#include "protocols.h"
#include "privilege_db.h"
#include "cynara.h"
#include "permissible-set.h"
#include "smack-exceptions.h"
#include "smack-rules.h"
#include "smack-labels.h"
#include "security-manager.h"
#include "tzplatform-config.h"
#include "utils.h"
#include "privilege-info.h"

#include "service_impl.h"

namespace SecurityManager {

namespace {

bool fileExists(const std::string &path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0) && S_ISREG(buffer.st_mode);
}

std::string realPath(const std::string &path)
{
    auto real_pathPtr = makeUnique(realpath(path.c_str(), nullptr), free);
    if (!real_pathPtr) {
        LogError("Error in realpath(): " << GetErrnoString(errno) << " for: " << path);
        return std::string();
    }

    return real_pathPtr.get();
}

class ScopedTransaction {
public:
    ScopedTransaction(PrivilegeDb &privilegeDb) : m_isCommited(false), m_privilegeDb(privilegeDb) {
        m_privilegeDb.BeginTransaction();
    }
    ScopedTransaction(const ScopedTransaction &other) = delete;
    ScopedTransaction& operation(const ScopedTransaction &other) = delete;

    void commit() {
        m_privilegeDb.CommitTransaction();
        m_isCommited = true;
    }
    ~ScopedTransaction() {
        if (!m_isCommited) {
            try {
                m_privilegeDb.RollbackTransaction();
            } catch (const SecurityManager::Exception &e) {
                LogError("Transaction rollback failed: " << e.GetMessage());
            } catch(...) {
                LogError("Transaction rollback failed with unknown exception");
            }
        }
    }
private:
    bool m_isCommited;
    PrivilegeDb &m_privilegeDb;
};

bool verifyAppDefinedPrivileges(app_inst_req &req) {
    std::vector<std::string> licenseVector;

    for (auto &e : req.appDefinedPrivileges) {
        // check if licenses are set for license-privileges
        if ((std::get<1>(e) == SM_APP_DEFINED_PRIVILEGE_TYPE_LICENSED)
            && (std::get<2>(e).empty()))
        {
            LogError("License privilege delivered empty license!");
            return false;
        }

        // check for collision with system privileges
        if (std::get<0>(e).find("http://tizen.org/privilege/") != std::string::npos) {
            LogError("App defined privilege could not contain: 'http://tizen.org/privilege'");
            return false;
        }

        if (std::get<1>(e) == SM_APP_DEFINED_PRIVILEGE_TYPE_LICENSED)
            licenseVector.push_back(std::get<2>(e));
    }

    // get license from 'client' privileges
    for (auto &e : req.privileges) {
        if (!e.second.empty())
            licenseVector.push_back(e.second);
    }

    // We need to verify licenses placement in filesystem
    // Each license must be marked as SECURITY_MANAGER_PATH_RO
    // and the path must be inside application directory.
    // If we put licenses in pkgPaths all of this will be done
    // during paths verification procedure.
    for (auto &e : licenseVector) {
        std::string tmp = realPath(e);
        if (tmp.empty())
            return false;
        req.pkgPaths.emplace_back(std::move(tmp), SECURITY_MANAGER_PATH_RO);
    }

    return true;
}

} // end of anonymous namespace

ServiceImpl::ServiceImpl()
{
}

ServiceImpl::~ServiceImpl()
{
}

int ServiceImpl::validatePolicy(const Credentials &creds, policy_entry &policyEntry, CynaraAdminPolicy &cyap)
{
    LogDebug("Authenticating and validating policy update request for user with id: " << creds.uid);
    LogDebug("[policy_entry] app: " << policyEntry.appName
            << " user: " << policyEntry.user
            << " privilege: " << policyEntry.privilege
            << " current: " << policyEntry.currentLevel
            << " max: " << policyEntry.maxLevel);

    //automagically fill missing fields:
    if (policyEntry.user.empty())
        policyEntry.user = std::to_string(creds.uid);

    bool forAdmin;
    int level;

    if (policyEntry.currentLevel.empty()) { //for admin
        if (policyEntry.appName.empty()
            || policyEntry.privilege.empty()) {
            LogError("Bad admin update request");
            return SECURITY_MANAGER_ERROR_BAD_REQUEST;
        }

        if (!policyEntry.maxLevel.compare(SECURITY_MANAGER_DELETE)) {
            level = CYNARA_ADMIN_DELETE;
        } else {
            try {
                level = m_cynaraAdmin.convertToPolicyType(policyEntry.maxLevel);
            } catch (const std::out_of_range& e) {
                LogError("policy max level cannot be: " << policyEntry.maxLevel);
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
            }
        }
        forAdmin = true;

    } else if (policyEntry.maxLevel.empty()) { //for self
        if (!policyEntry.appName.compare(SECURITY_MANAGER_ANY)
            || !policyEntry.privilege.compare(SECURITY_MANAGER_ANY)
            || policyEntry.appName.empty()
            || policyEntry.privilege.empty()) {
            LogError("Bad privacy manager update request");
            return SECURITY_MANAGER_ERROR_BAD_REQUEST;
        }

        if (!policyEntry.currentLevel.compare(SECURITY_MANAGER_DELETE)) {
            level = CYNARA_ADMIN_DELETE;
        } else {
            try {
                level = m_cynaraAdmin.convertToPolicyType(policyEntry.currentLevel);
            } catch (const std::out_of_range& e) {
                LogError("policy current level cannot be: " << policyEntry.currentLevel);
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
            }
        }
        forAdmin = false;

    } else { //neither => bad request
        return SECURITY_MANAGER_ERROR_BAD_REQUEST;
    }

    if (!policyEntry.user.compare(SECURITY_MANAGER_ANY))
        policyEntry.user = CYNARA_ADMIN_WILDCARD;
    if (!policyEntry.privilege.compare(SECURITY_MANAGER_ANY))
        policyEntry.privilege = CYNARA_ADMIN_WILDCARD;

    const std::string &privilege = (forAdmin || policyEntry.user.compare(std::to_string(creds.uid))) ?
            Config::PRIVILEGE_POLICY_ADMIN : Config::PRIVILEGE_POLICY_USER;
    if (!authenticate(creds, privilege)) {
        LogError("Not enough privilege to enforce user policy");
        return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
    }

    std::string cynaraClient;
    if (policyEntry.appName.compare(SECURITY_MANAGER_ANY)) {
        cynaraClient = getAppProcessLabel(policyEntry.appName);
        if (cynaraClient.empty()) {
            LogWarning("Cannot set policy for unknown application " << policyEntry.appName);
            return SECURITY_MANAGER_ERROR_APP_UNKNOWN;
        }
    } else {
        cynaraClient = CYNARA_ADMIN_WILDCARD;
    }

    cyap = std::move(CynaraAdminPolicy(
        cynaraClient,
        policyEntry.user,
        policyEntry.privilege,
        level,
        (forAdmin)?CynaraAdmin::Buckets.at(Bucket::ADMIN):CynaraAdmin::Buckets.at(Bucket::PRIVACY_MANAGER)));

    LogDebug("Policy update request authenticated and validated successfully");
    return SECURITY_MANAGER_SUCCESS;
}

std::string ServiceImpl::getAppProcessLabel(const std::string &appName, const std::string &pkgName)
{
    bool isPkgHybrid = m_privilegeDb.IsPackageHybrid(pkgName);
    return SmackLabels::generateProcessLabel(appName, pkgName, isPkgHybrid);
}

std::string ServiceImpl::getAppProcessLabel(const std::string &appName)
{
    std::string pkgName;
    m_privilegeDb.GetAppPkgName(appName, pkgName);
    if (pkgName.empty()) {
        LogWarning("Cannot create label for unknown application: " << appName);
        return "";
    }
    return getAppProcessLabel(appName, pkgName);
}

bool ServiceImpl::sharingExists(const std::string &targetAppName, const std::string &path)
{
    int targetPathCount;
    m_privilegeDb.GetTargetPathSharingCount(targetAppName, path, targetPathCount);
    return targetPathCount != 0;
}

void ServiceImpl::getPkgsProcessLabels(const std::vector<PkgInfo> &pkgsInfo, SmackRules::PkgsLabels &pkgsLabels)
{
    pkgsLabels.resize(pkgsInfo.size());
    for (size_t i = 0; i < pkgsInfo.size(); ++i) {
        pkgsLabels[i].first = pkgsInfo[i].name;
        m_privilegeDb.GetPkgApps(pkgsLabels[i].first, pkgsLabels[i].second);
        for (auto &appName : pkgsLabels[i].second) {
            std::string label = SmackLabels::generateProcessLabel(appName, pkgsLabels[i].first,
                                                                  pkgsInfo[i].hybrid);
            appName = label;
        }
    }
}

bool ServiceImpl::authenticate(const Credentials &creds, const std::string &privilege)
{
    if (creds.authenticated)
        return true;
    return m_cynara.check(creds.label, privilege,
        std::to_string(creds.uid), std::to_string(creds.pid));
}

uid_t ServiceImpl::getGlobalUserId(void)
{
    static uid_t globaluid = TizenPlatformConfig::getUid(TZ_SYS_GLOBALAPP_USER);
    return globaluid;
}

bool ServiceImpl::isSubDir(const std::string &parent, const std::string &subdir)
{
    const char *str1 = parent.c_str();
    const char *str2 = subdir.c_str();

    while (*str1 && *str2)
        if (*str1++ != *str2++)
            return false;

    return (*str2 == '/' || *str1 == *str2);
}

bool ServiceImpl::containSubDir(const std::string &parent, const pkg_paths &paths)
{

    for (auto path : paths) {
        if (isSubDir(parent, path.first))
            return true;
    }
    return false;
}

bool ServiceImpl::getUserPkgDir(const uid_t &uid,
                                const std::string &pkgName,
                                app_install_type installType,
                                std::string &userPkgDir)
{
    TizenPlatformConfig tpc(uid);

    enum tzplatform_variable id;

    switch (installType) {
    case SM_APP_INSTALL_LOCAL:
        id = TZ_USER_APP;
        break;
    case SM_APP_INSTALL_GLOBAL:
        id = TZ_SYS_RW_APP;
        break;
    case SM_APP_INSTALL_PRELOADED:
        id = TZ_SYS_RO_APP;
        break;
    default:
        LogError("Unsupported installation type: " << installType);
        return false;
    }

    userPkgDir = std::move(realPath(tpc.ctxGetEnv(id)));
    if (userPkgDir.empty())
        return false;

    userPkgDir.append("/").append(pkgName);

    return true;
}

bool ServiceImpl::getSkelPkgDir(const std::string &pkgName,
                                std::string &skelPkgDir)
{
    std::string app = TizenPlatformConfig::getEnv(TZ_USER_APP);
    std::string home = TizenPlatformConfig::getEnv(TZ_USER_HOME);
    std::string real_skel_dir = std::move(realPath(Config::SKEL_DIR));
    if (app.empty() || home.empty() || real_skel_dir.empty()) {
        LogError("Unable to get skel pkg dir.");
        return false;
    }

    skelPkgDir.assign(app);
    skelPkgDir.replace(0, home.length(), real_skel_dir);
    skelPkgDir.append("/").append(pkgName);

    return true;
}

void ServiceImpl::setRequestDefaultValues(uid_t& uid, int& installationType)
{
    uid_t globalUid = getGlobalUserId();

    if (installationType == SM_APP_INSTALL_NONE)
        installationType = ((uid == 0) || (uid == globalUid)) ? SM_APP_INSTALL_GLOBAL :
                SM_APP_INSTALL_LOCAL;
    if ((installationType == SM_APP_INSTALL_GLOBAL)
        || (installationType == SM_APP_INSTALL_PRELOADED))
        uid = globalUid;
}

bool ServiceImpl::authCheck(const Credentials &creds,
                            const uid_t& uid,
                            int installationType)
{
    if (installationType == SM_APP_INSTALL_LOCAL) {
        if (!authenticate(creds, Config::PRIVILEGE_APPINST_USER)) {
            LogError("Caller is not permitted to manage local applications");
            return false;
        }
        if (uid != creds.uid && !authenticate(creds, Config::PRIVILEGE_USER_ADMIN)) {
            LogError("Caller is not permitted to manage applications for other users");
            return false;
        }
        if (uid == getGlobalUserId()) {
            LogError("Request local installation for global uid=" << uid);
            return false;
        }
    } else {
        if (!authenticate(creds, Config::PRIVILEGE_APPINST_ADMIN)) {
            LogError("Caller is not permitted to manage global applications");
            return false;
        }
    }

    return true;
}

bool ServiceImpl::pathsCheck(const pkg_paths &requestedPaths,
    const std::vector<std::string> &allowedDirs)
{
    LogDebug("Validating installation paths. Allowed directories: ");
    for (const auto &dir : allowedDirs)
        LogDebug("- " << dir);

    for (const auto &path : requestedPaths) {
        LogDebug("Requested path is '" << path.first.c_str() << "'");
        bool allowed = std::any_of(allowedDirs.begin(), allowedDirs.end(),
            std::bind(isSubDir, std::placeholders::_1, realPath(path.first)));

        if (!allowed) {
            LogWarning("Installation path " << path.first << " is outside allowed directories");
            return false;
        }
    }
    return true;
}

int ServiceImpl::labelPaths(const pkg_paths &paths,
                            const std::string &pkgName,
                            app_install_type installationType,
                            const uid_t &uid)
{
    try {
        std::string pkgBasePath;
        int authorId;

        if (!m_privilegeDb.PkgNameExists(pkgName)) {
            LogError("No such package: " << pkgName);
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        m_privilegeDb.GetPkgAuthorId(pkgName, authorId);

        if (!getUserPkgDir(uid, pkgName, installationType, pkgBasePath))
            return SECURITY_MANAGER_ERROR_SERVER_ERROR;

        // check if paths are inside
        bool pathsOK;
        if (installationType == SM_APP_INSTALL_LOCAL) {
            pathsOK = pathsCheck(paths, {pkgBasePath});
        } else {
            std::string skelPkgBasePath;
            if (!getSkelPkgDir(pkgName, skelPkgBasePath))
                return SECURITY_MANAGER_ERROR_SERVER_ERROR;
            pathsOK = pathsCheck(paths, {pkgBasePath, skelPkgBasePath});
        }

        if (!pathsOK)
            return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;

        if (containSubDir(pkgBasePath, paths))
            SmackLabels::setupPkgBasePath(pkgBasePath);

        // register paths
        for (const auto &pkgPath : paths) {
            const std::string &path = pkgPath.first;
            app_install_path_type pathType = static_cast<app_install_path_type>(pkgPath.second);
            SmackLabels::setupPath(pkgName, path, pathType, authorId);
        }
        return SECURITY_MANAGER_SUCCESS;
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Database error: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidParam &e) {
        LogError("Invalid parameter during labeling: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    } catch (const SmackException::InvalidPathType &e) {
        LogError("Invalid path type: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    } catch (const SmackException::Base &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SETTING_FILE_LABEL_FAILED;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }
}

bool ServiceImpl::isSharedRO(const pkg_paths& paths)
{
    for (const auto& pkgPath : paths) {
        auto pathType = static_cast<app_install_path_type>(pkgPath.second);
        if (pathType == SECURITY_MANAGER_PATH_OWNER_RW_OTHER_RO)
            return true;
    }

    return false;
}

void ServiceImpl::getPkgLabels(const std::string &pkgName, SmackRules::Labels &pkgsLabels)
{
    bool isPkgHybrid = m_privilegeDb.IsPackageHybrid(pkgName);
    if (isPkgHybrid) {
        std::vector<std::string> apps;
        m_privilegeDb.GetPkgApps(pkgName, apps);
        for (auto &app : apps) {
            auto appLabel = SmackLabels::generateProcessLabel(app, pkgName, isPkgHybrid);
            app = appLabel;
        }
        pkgsLabels = std::move(apps);
    } else {
        pkgsLabels.push_back(SmackLabels::generateProcessLabel("", pkgName, false));
    }
}

void ServiceImpl::updatePermissibleSet(uid_t uid, int type)
{
    std::vector<std::string> userPkgs;
    m_privilegeDb.GetUserPkgs(uid, userPkgs);
    std::vector<std::string> labelsForUser;
    for (const auto &pkg : userPkgs) {
        std::vector<std::string> pkgLabels;
        getPkgLabels(pkg, pkgLabels);
        labelsForUser.insert(labelsForUser.end(), pkgLabels.begin(), pkgLabels.end());
    }
    PermissibleSet::updatePermissibleFile(uid, type, labelsForUser);
}

int ServiceImpl::appInstall(const Credentials &creds, app_inst_req &&req)
{
    SmackRules::Labels pkgLabels;
    std::string cynaraUserStr;
    std::string pkgBasePath;
    std::string appLabel;
    std::string pkgLabel;
    SmackRules::PkgsLabels pkgsProcessLabels;
    int authorId;
    std::vector<PkgInfo> pkgsInfo;
    bool hasSharedRO = isSharedRO(req.pkgPaths);

    try {
        std::vector<std::string> privilegeList;
        privilegeList.reserve(req.privileges.size());

        if (!verifyAppDefinedPrivileges(req))
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;

        for (auto &e : req.privileges)
            privilegeList.push_back(e.first);

        setRequestDefaultValues(req.uid, req.installationType);

        LogDebug("Install parameters: appName: " << req.appName << ", pkgName: " << req.pkgName
                 << ", uid: " << req.uid << ", target Tizen API ver: "
                 << (req.tizenVersion.empty() ? "unknown" : req.tizenVersion));

        if (!authCheck(creds, req.uid, req.installationType)) {
            LogError("Request from uid=" << creds.uid << ", Smack=" << creds.label <<
                " for app installation denied");
            return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;
        }

        appLabel = SmackLabels::generateProcessLabel(req.appName, req.pkgName, req.isHybrid);
        pkgLabel = SmackLabels::generatePathRWLabel(req.pkgName);
        LogDebug("Generated install parameters: app label: " << appLabel <<
                 ", pkg label: " << pkgLabel);

        ScopedTransaction trans(m_privilegeDb);

        m_privilegeDb.AddApplication(req.appName, req.pkgName, req.uid,
                                     req.tizenVersion, req.authorName, req.isHybrid);
        /* Get all application ids in the package to generate rules withing the package */
        getPkgLabels(req.pkgName, pkgLabels);
        m_privilegeDb.GetPkgAuthorId(req.pkgName, authorId);

        AppDefinedPrivilegesVector oldAppDefinedPrivileges;
        m_privilegeDb.GetAppDefinedPrivileges(req.appName, req.uid, oldAppDefinedPrivileges);

        bool global = req.installationType == SM_APP_INSTALL_GLOBAL ||
                      req.installationType == SM_APP_INSTALL_PRELOADED;
        m_cynaraAdmin.updateAppPolicy(appLabel, global, req.uid, privilegeList,
                                      oldAppDefinedPrivileges, req.appDefinedPrivileges);

        m_privilegeDb.RemoveAppDefinedPrivileges(req.appName, req.uid);
        m_privilegeDb.AddAppDefinedPrivileges(req.appName, req.uid, req.appDefinedPrivileges);

        m_privilegeDb.RemoveClientPrivileges(req.appName, req.uid);
        for (auto &e : req.privileges) {
            if (!e.second.empty())
                m_privilegeDb.AddClientPrivilege(req.appName, req.uid, e.first, e.second);
        }

        if (hasSharedRO)
            m_privilegeDb.SetSharedROPackage(req.pkgName);

        m_privilegeDb.GetPackagesInfo(pkgsInfo);
        getPkgsProcessLabels(pkgsInfo, pkgsProcessLabels);

        // WTF? Why this commit is here? Shouldn't it be at the end of this function?
        trans.commit();
        LogDebug("Application installation commited to database");
        updatePermissibleSet(req.uid, req.installationType);
    } catch (const PrivilegeDb::Exception::IOError &e) {
        LogError("Cannot access application database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::ConstraintError &e) {
        LogError("Application conflicts with existing one: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        LogError("Error while saving application info to database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PrivilegeInfo::Exception::Base &e) {
        LogError("Error while getting privilege information: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PermissibleSet::PermissibleSetException::Base &e) {
        LogError("Error while updating permissible file: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    int ret = labelPaths(req.pkgPaths,
                         req.pkgName,
                         static_cast<app_install_type>(req.installationType),
                         req.uid);
    if (ret != SECURITY_MANAGER_SUCCESS)
        return ret;

    try {
        LogDebug("Adding Smack rules for new appName: " << req.appName << " with pkgName: "
                << req.pkgName << ".");
        SmackRules::installApplicationRules(req.appName, appLabel, req.pkgName,
                                            authorId, pkgLabels);

        SmackRules::generateSharedRORules(pkgsProcessLabels, pkgsInfo);

        SmackRules::mergeRules();
    } catch (const SmackException::InvalidParam &e) {
        LogError("Invalid paramater during labeling: " << e.GetMessage());
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    } catch (const SmackException::Base &e) {
        LogError("Error while applying Smack policy for application: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SETTING_FILE_LABEL_FAILED;
    } catch (const SecurityManager::Exception &e) {
        LogError("Security Manager exception: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::appUninstall(const Credentials &creds, app_inst_req &&req)
{
    std::string processLabel;
    SmackRules::Labels pkgLabels;
    bool removeApp = false;
    bool removePkg = false;
    bool removeAuthor = false;
    std::string cynaraUserStr;
    SmackRules::PkgsLabels pkgsProcessLabels;
    std::map<std::string, std::vector<std::string>> asOwnerSharing;
    std::map<std::string, std::vector<std::string>> asTargetSharing;
    int authorId;
    bool isPkgHybrid;
    std::vector<PkgInfo> pkgsInfo;

    setRequestDefaultValues(req.uid, req.installationType);

    LogDebug("Uninstall parameters: appName=" << req.appName << ", uid=" << req.uid);

    if (!authCheck(creds, req.uid, req.installationType)) {
        LogError("Request from uid=" << creds.uid << ", Smack=" << creds.label <<
            " for app uninstallation denied");
        return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;
    }

    try {
        ScopedTransaction trans(m_privilegeDb);
        std::string pkgName;
        m_privilegeDb.GetAppPkgName(req.appName, pkgName);
        if (pkgName.empty()) {
            LogWarning("Application " << req.appName << " not found in database "
                       "while uninstalling");
            return SECURITY_MANAGER_SUCCESS;
        }
        if (req.pkgName.empty()) {
            req.pkgName = pkgName;
        } else if (req.pkgName != pkgName){
            LogWarning("Application " << req.appName << " exists, but wrong package id "
                        << req.pkgName << " is passed, should be: " << pkgName);
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        isPkgHybrid = m_privilegeDb.IsPackageHybrid(req.pkgName);
        processLabel = getAppProcessLabel(req.appName, req.pkgName);
        LogDebug("Generated uninstall parameters: pkgName=" << req.pkgName
            << " Smack label=" << processLabel);

        /* Before we remove the app from the database, let's fetch all apps in the package
            that this app belongs to, this will allow us to remove all rules withing the
            package that the app appears in */
        m_privilegeDb.GetPkgAuthorId(req.pkgName, authorId);
        getPkgLabels(req.pkgName, pkgLabels);
        m_privilegeDb.GetAppVersion(req.appName, req.tizenVersion);
        m_privilegeDb.GetPrivateSharingForOwner(req.appName, asOwnerSharing);
        m_privilegeDb.GetPrivateSharingForTarget(req.appName, asTargetSharing);

        for (const auto &targetPathsInfo : asOwnerSharing) {
            const auto &targetAppName = targetPathsInfo.first;
            const auto &paths = targetPathsInfo.second;
            // Squash sharing - change counter to 1, so dropPrivatePathSharing will completely clean it
            for (const auto &path : paths) {
                m_privilegeDb.SquashSharing(targetAppName, path);
                auto targetAppLabel = getAppProcessLabel(targetAppName);
                int ret = dropOnePrivateSharing(req.appName, req.pkgName, pkgLabels,
                                                targetAppName, targetAppLabel, path);
                if (ret != SECURITY_MANAGER_SUCCESS) {
                    //Ignore error, we want to drop as much as we can
                    LogError("Couldn't drop sharing between " << req.appName << " and " << targetAppName);
                }
            }
        }

        for (const auto &ownerPathsInfo : asTargetSharing) {
            const auto &ownerAppName = ownerPathsInfo.first;
            const auto &paths = ownerPathsInfo.second;
            // Squash sharing - change counter to 1, so dropPrivatePathSharing will completely clean it
            std::string ownerPkgName;
            SmackRules::Labels ownerPkgLabels;
            m_privilegeDb.GetAppPkgName(ownerAppName, ownerPkgName);
            getPkgLabels(ownerPkgName, ownerPkgLabels);
            for (const auto &path : paths) {
                m_privilegeDb.SquashSharing(req.appName, path);
                    int ret = dropOnePrivateSharing(ownerAppName, ownerPkgName, ownerPkgLabels,
                                                    req.appName, processLabel, path);
                    if (ret != SECURITY_MANAGER_SUCCESS) {
                        //Ignore error, we want to drop as much as we can
                        LogError("Couldn't drop sharing between " << req.appName << " and " << ownerAppName);
                    }
                }
        }

        AppDefinedPrivilegesVector oldAppDefinedPrivileges;
        m_privilegeDb.GetAppDefinedPrivileges(req.appName, req.uid, oldAppDefinedPrivileges);

        m_privilegeDb.RemoveApplication(req.appName, req.uid, removeApp, removePkg, removeAuthor);

        m_privilegeDb.GetPackagesInfo(pkgsInfo);
        getPkgsProcessLabels(pkgsInfo, pkgsProcessLabels);

        bool global = req.installationType == SM_APP_INSTALL_GLOBAL ||
                      req.installationType == SM_APP_INSTALL_PRELOADED;
        m_cynaraAdmin.updateAppPolicy(processLabel, global, req.uid, std::vector<std::string>(),
                                      oldAppDefinedPrivileges, AppDefinedPrivilegesVector(), true);
        trans.commit();

        LogDebug("Application uninstallation commited to database");
        updatePermissibleSet(req.uid, req.installationType);
    } catch (const PrivilegeDb::Exception::IOError &e) {
        LogError("Cannot access application database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while removing application info from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PrivilegeInfo::Exception::Base &e) {
        LogError("Error while getting privilege information: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        LogError("Error while setting Cynara rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PermissibleSet::PermissibleSetException::Base &e) {
        LogError("Error while updating permissible file: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation while setting Cynara rules for application: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    try {
        if (removeApp) {
            LogDebug("Removing Smack rules for appName " << req.appName);
            if (isPkgHybrid || removePkg) {
                /*
                 * Nonhybrid apps have the same label, so revoking it is unnecessary
                 * unless whole packagee is being removed.
                 */
                SmackRules::uninstallApplicationRules(req.appName, processLabel);
            }
            LogDebug("Removing Smack rules for pkgName " << req.pkgName);
            SmackRules::uninstallPackageRules(req.pkgName);
            if (!removePkg) {
                LogDebug("Recreating Smack rules for pkgName " << req.pkgName);
                pkgLabels.erase(std::remove(pkgLabels.begin(), pkgLabels.end(), processLabel),
                                pkgLabels.end());
                SmackRules::updatePackageRules(req.pkgName, pkgLabels);
            }

            SmackRules::generateSharedRORules(pkgsProcessLabels, pkgsInfo);
            if (removePkg)
                SmackRules::revokeSharedRORules(pkgsProcessLabels, req.pkgName);
        }

        if (authorId != -1 && removeAuthor) {
            LogDebug("Removing Smack rules for authorId " << authorId);
            SmackRules::uninstallAuthorRules(authorId);
        }

        SmackRules::mergeRules();
    } catch (const SmackException::Base &e) {
        LogError("Error while removing Smack rules for application: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SETTING_FILE_LABEL_FAILED;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getPkgName(const std::string &appName, std::string &pkgName)
{
    LogDebug("appName: " << appName);

    try {
        m_privilegeDb.GetAppPkgName(appName, pkgName);
        if (pkgName.empty()) {
            LogWarning("Application " << appName << " not found in database");
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        } else {
            LogDebug("pkgName: " << pkgName);
        }
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting pkgName from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_SUCCESS;
}

template <typename T>
static void vectorRemoveDuplicates(std::vector<T> &vec)
{
    std::sort(vec.begin(), vec.end());
    vec.erase(std::unique(vec.begin(), vec.end()), vec.end());
}

int ServiceImpl::getAppGroups(const Credentials &creds, const std::string &appName,
    std::vector<std::string> &groups)
{
    try {
        LogDebug("appName: " << appName);
        std::string appProcessLabel = getAppProcessLabel(appName);
        LogDebug("smack label: " << appProcessLabel);

        std::vector<std::string> privileges;

        std::string uidStr = std::to_string(creds.uid);
        m_cynaraAdmin.getAppPolicy(appProcessLabel, uidStr, privileges);
        m_cynaraAdmin.getAppPolicy(appProcessLabel, CYNARA_ADMIN_WILDCARD, privileges);

        vectorRemoveDuplicates(privileges);

        std::string pidStr = std::to_string(creds.pid);
        for (const auto &privilege : privileges) {
            std::vector<std::string> privGroups;
            m_privilegeDb.GetPrivilegeGroups(privilege, privGroups);
            if (!privGroups.empty()) {
                LogDebug("Considering privilege " << privilege << " with " <<
                    privGroups.size() << " groups assigned");

                if (m_cynara.check(appProcessLabel, privilege, uidStr, pidStr)) {
                    groups.insert(groups.end(),
                        std::make_move_iterator(privGroups.begin()),
                        std::make_move_iterator(privGroups.end()));
                    LogDebug("Cynara allowed, adding groups");
                } else {
                    LogDebug("Cynara denied, not adding groups");
                }
            }
        }
        vectorRemoveDuplicates(groups);
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Database error: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::userAdd(const Credentials &creds, uid_t uidAdded, int userType)
{
    if (!authenticate(creds, Config::PRIVILEGE_USER_ADMIN)) {
        LogError("Caller is not permitted to manage users");
        return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;
    }
    try {
        m_cynaraAdmin.userInit(uidAdded, static_cast<security_manager_user_type>(userType));
        PermissibleSet::initializeUserPermissibleFile(uidAdded);
    } catch (CynaraException::InvalidParam &e) {
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    } catch (const PermissibleSet::PermissibleSetException::FileInitError &e) {
        LogError("Error while adding user: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SETTING_FILE_LABEL_FAILED;
    } catch (const SmackException::FileError &e) {
        LogError("Error while adding user: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SETTING_FILE_LABEL_FAILED;
    } catch (const PrivilegeInfo::Exception::Base &e) {
        LogError("Error while getting privilege information: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const TizenPlatformConfig::Exception::Base &e) {
        LogError("Error while adding user: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::exception &e) {
        LogError("Memory allocation error while adding user: " << e.what());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }
    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::userDelete(const Credentials &creds, uid_t uidDeleted)
{
    int ret = SECURITY_MANAGER_SUCCESS;

    if (!authenticate(creds, Config::PRIVILEGE_USER_ADMIN)) {
        LogError("Caller is not permitted to manage users");
        return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;
    }

    /*Uninstall all user apps*/
    std::vector<std::string> userApps;
    try {
        m_privilegeDb.GetUserApps(uidDeleted, userApps);
        PermissibleSet::removeUserPermissibleFile(uidDeleted);
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting user apps from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PermissibleSet::PermissibleSetException::FileRemoveError &e) {
        LogError("Error while removing user: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_FILE_DELETE_FAILED;
    } catch (const TizenPlatformConfig::Exception::Base &e) {
        LogError("Error while adding user: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::exception &e) {
        LogError("Memory allocation error while deleting user: " << e.what());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    // Don't check whether the caller may uninstall apps of the removed user
    Credentials credsTmp(creds);
    credsTmp.authenticated = true;
    for (const auto &app : userApps) {
        app_inst_req req;
        req.uid = uidDeleted;
        req.appName = app;
        if (appUninstall(credsTmp, std::move(req)) != SECURITY_MANAGER_SUCCESS) {
        /*if uninstallation of this app fails, just go on trying to uninstall another ones.
        we do not have anything special to do about that matter - user will be deleted anyway.*/
            ret = SECURITY_MANAGER_ERROR_SERVER_ERROR;
        }
    }

    m_cynaraAdmin.userRemove(uidDeleted);

    return ret;
}

int ServiceImpl::policyUpdate(const Credentials &creds, const std::vector<policy_entry> &policyEntries)
{
    try {
        if (policyEntries.size() == 0) {
            LogError("Validation failed: policy update request is empty");
            return SECURITY_MANAGER_ERROR_BAD_REQUEST;
        };

        std::vector<CynaraAdminPolicy> validatedPolicies;

        for (auto &entry : const_cast<std::vector<policy_entry>&>(policyEntries)) {
            CynaraAdminPolicy cyap;
            int ret = validatePolicy(creds, entry, cyap);
            if (ret != SECURITY_MANAGER_SUCCESS)
                return ret;

            validatedPolicies.push_back(std::move(cyap));
        };

        // Apply updates
        m_cynaraAdmin.setPolicies(validatedPolicies);

    } catch (const CynaraException::Base &e) {
        LogError("Error while updating Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while updating Cynara rules: " << e.what());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getConfiguredPolicy(const Credentials &creds, bool forAdmin,
    const policy_entry &filter, std::vector<policy_entry> &policyEntries)
{
    try {
        std::string uidStr = std::to_string(creds.uid);
        std::string pidStr = std::to_string(creds.pid);

        LogDebug("Filter is: C: " << filter.appName
                    << ", U: " << filter.user
                    << ", P: " << filter.privilege
                    << ", current: " << filter.currentLevel
                    << ", max: " << filter.maxLevel);

        std::vector<CynaraAdminPolicy> listOfPolicies;

        //convert appName to smack label
        std::string appProcessLabel = filter.appName.compare(SECURITY_MANAGER_ANY) ?
                                getAppProcessLabel(filter.appName) : CYNARA_ADMIN_ANY;
        std::string user = filter.user.compare(SECURITY_MANAGER_ANY) ? filter.user : CYNARA_ADMIN_ANY;
        std::string privilege = filter.privilege.compare(SECURITY_MANAGER_ANY) ? filter.privilege : CYNARA_ADMIN_ANY;

        LogDebug("App: " << filter.appName << ", Label: " << appProcessLabel);

        if (forAdmin) {
            if (!authenticate(creds, Config::PRIVILEGE_POLICY_ADMIN)) {
                LogError("Not enough privilege to access admin enforced policies");
                return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
            }

            //Fetch privileges from ADMIN bucket
            m_cynaraAdmin.listPolicies(
                CynaraAdmin::Buckets.at(Bucket::ADMIN),
                appProcessLabel,
                user,
                privilege,
                listOfPolicies);
            LogDebug("ADMIN - number of policies matched: " << listOfPolicies.size());
        } else {
            if (!authenticate(creds, Config::PRIVILEGE_POLICY_USER)) {
                LogError("Not enough privilege to access user enforced policies");
                return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
            }

            if (uidStr.compare(user)) {
                if (!authenticate(creds, Config::PRIVILEGE_POLICY_ADMIN)) {
                    LogWarning("Not enough privilege to access other user's personal policies");
                    return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
                };
            };
            //Fetch privileges from PRIVACY_MANAGER bucket
            m_cynaraAdmin.listPolicies(
                CynaraAdmin::Buckets.at(Bucket::PRIVACY_MANAGER),
                appProcessLabel,
                user,
                privilege,
                listOfPolicies);
            LogDebug("PRIVACY MANAGER - number of policies matched: " << listOfPolicies.size());
        };

        for (const auto &policy : listOfPolicies) {
            //ignore "jump to bucket" entries
            if (policy.result ==  CYNARA_ADMIN_BUCKET)
                continue;

            policy_entry pe;
            std::vector<std::string> appNames;
            std::string appName, pkgName;

            if (strcmp(policy.client, CYNARA_ADMIN_WILDCARD)) {
                SmackLabels::generateAppPkgNameFromLabel(policy.client, appName, pkgName);
                if (!appName.empty()) {
                    // Hybrid app
                    appNames.push_back(appName);
                } else {
                    if (filter.appName == SECURITY_MANAGER_ANY) {
                        // If user requested policy for all apps, we have to demangle pkgName to
                        // set of appNames in case of non-hybrid apps
                        m_privilegeDb.GetPkgApps(pkgName, appNames);
                    } else {
                        // If user requested policy for specific appName, we have to copy
                        // appName from filter for non-hybrid apps
                        appNames.push_back(filter.appName);
                    }
                }
            } else {
                // Cynara wildcard -> SM any
                appNames.push_back(SECURITY_MANAGER_ANY);
            }

            for (const auto &app : appNames) {
                pe.appName = app;
                pe.user =  strcmp(policy.user, CYNARA_ADMIN_WILDCARD) ? policy.user : SECURITY_MANAGER_ANY;
                pe.privilege = strcmp(policy.privilege, CYNARA_ADMIN_WILDCARD) ? policy.privilege : pe.privilege = SECURITY_MANAGER_ANY;
                pe.currentLevel = m_cynaraAdmin.convertToPolicyDescription(policy.result);

                if (!forAdmin) {
                    // All policy entries in PRIVACY_MANAGER should be fully-qualified
                    pe.maxLevel = m_cynaraAdmin.convertToPolicyDescription(
                        m_cynaraAdmin.getPrivilegeManagerMaxLevel(
                            policy.client, policy.user, policy.privilege));
                } else {
                    // Cannot reliably calculate maxLavel for policies from ADMIN bucket
                    pe.maxLevel = m_cynaraAdmin.convertToPolicyDescription(CYNARA_ADMIN_ALLOW);
                }


                LogDebug(
                    "[policy_entry] app: " << pe.appName
                    << " user: " << pe.user
                    << " privilege: " << pe.privilege
                    << " current: " << pe.currentLevel
                    << " max: " << pe.maxLevel);

                policyEntries.push_back(pe);
            }
        };

    } catch (const CynaraException::Base &e) {
        LogError("Error while listing Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while listing Cynara rules: " << e.what());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }


    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getPolicy(const Credentials &creds, const policy_entry &filter,
    std::vector<policy_entry> &policyEntries)
{
    try {
        std::string uidStr = std::to_string(creds.uid);
        std::string pidStr = std::to_string(creds.pid);

        if (!authenticate(creds, Config::PRIVILEGE_POLICY_USER)) {
            LogWarning("Not enough permission to call: " << __FUNCTION__);
            return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
        };

        LogDebug("Filter is: C: " << filter.appName
                    << ", U: " << filter.user
                    << ", P: " << filter.privilege
                    << ", current: " << filter.currentLevel
                    << ", max: " << filter.maxLevel);

        std::vector<uid_t> listOfUsers;

        if (authenticate(creds, Config::PRIVILEGE_POLICY_ADMIN)) {
            LogDebug("User is privileged");
            if (filter.user.compare(SECURITY_MANAGER_ANY)) {
                LogDebug("Limitting Cynara query to user: " << filter.user);
                try {
                    listOfUsers.push_back(static_cast<uid_t>(std::stoul(filter.user)));
                } catch (std::invalid_argument &e) {
                    LogError("Invalid UID: " << e.what());
                };
            } else {
                m_cynaraAdmin.listUsers(listOfUsers);
            }
        } else {
            LogWarning("Not enough privilege to fetch user policy for all users by user: " << creds.uid);
            LogDebug("Fetching personal policy for user: " << creds.uid);
            listOfUsers.push_back(creds.uid);
        };
        LogDebug("Fetching policy for " << listOfUsers.size() << " users");

        for (const uid_t &user : listOfUsers) {
            LogDebug("User: " << user);
            std::string userStr = std::to_string(user);
            std::vector<std::string> listOfApps;

            if (filter.appName.compare(SECURITY_MANAGER_ANY)) {
                LogDebug("Limitting Cynara query to app: " << filter.appName);
                listOfApps.push_back(filter.appName);
            } else {
                m_privilegeDb.GetUserApps(user, listOfApps);
                LogDebug("Found apps: " << listOfApps.size());
            };

            for (const std::string &appName : listOfApps) {
                LogDebug("App: " << appName);
                std::string appProcessLabel = getAppProcessLabel(appName);
                std::vector<std::string> listOfPrivileges;

                m_cynaraAdmin.getAppPolicy(appProcessLabel, userStr, listOfPrivileges);
                m_cynaraAdmin.getAppPolicy(appProcessLabel, CYNARA_ADMIN_WILDCARD, listOfPrivileges);

                if (filter.privilege.compare(SECURITY_MANAGER_ANY)) {
                    LogDebug("Limitting Cynara query to privilege: " << filter.privilege);
                    // FIXME: this filtering should be already performed by method fetching the privileges
                    if (std::find(listOfPrivileges.begin(), listOfPrivileges.end(),
                        filter.privilege) == listOfPrivileges.end()) {
                        LogDebug("Application " << appName <<
                            " doesn't have the filteres privilege " << filter.privilege);
                        continue;
                    }
                    listOfPrivileges.clear();
                    listOfPrivileges.push_back(filter.privilege);
                }

                LogDebug("Privileges matching filter - " << filter.privilege << ": " << listOfPrivileges.size());

                for (const std::string &privilege : listOfPrivileges) {
                    LogDebug("Privilege: " << privilege);
                    policy_entry pe;

                    pe.appName = appName;
                    pe.user = userStr;
                    pe.privilege = privilege;

                    pe.currentLevel = m_cynaraAdmin.convertToPolicyDescription(
                        m_cynaraAdmin.getPrivilegeManagerCurrLevel(
                            appProcessLabel, userStr, privilege));

                    pe.maxLevel = m_cynaraAdmin.convertToPolicyDescription(
                        m_cynaraAdmin.getPrivilegeManagerMaxLevel(
                            appProcessLabel, userStr, privilege));

                    LogDebug(
                        "[policy_entry] app: " << pe.appName
                        << " user: " << pe.user
                        << " privilege: " << pe.privilege
                        << " current: " << pe.currentLevel
                        << " max: " << pe.maxLevel);

                    policyEntries.push_back(pe);
                };
            };
        };

    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting application privileges from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const CynaraException::Base &e) {
        LogError("Error while listing Cynara rules: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation error while listing Cynara rules: " << e.what());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::policyGetDesc(std::vector<std::string> &levels)
{
    int ret = SECURITY_MANAGER_SUCCESS;

    try {
        m_cynaraAdmin.listPoliciesDescriptions(levels);
    } catch (const CynaraException::OutOfMemory &e) {
        LogError("Error - out of memory while querying Cynara for policy descriptions list: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const CynaraException::InvalidParam &e) {
        LogError("Error - invalid parameter while querying Cynara for policy descriptions list: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    } catch (const CynaraException::ServiceNotAvailable &e) {
        LogError("Error - service not available while querying Cynara for policy descriptions list: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_NO_SUCH_SERVICE;
    } catch (const CynaraException::Base &e) {
        LogError("Error while getting policy descriptions list from Cynara: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return ret;
}

int ServiceImpl::policyGetGroups(std::vector<std::string> &groups)
{
    int ret = SECURITY_MANAGER_SUCCESS;

    try {
        m_privilegeDb.GetGroups(groups);
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting groups from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return ret;
}

int ServiceImpl::policyGroupsForUid(uid_t uid, std::vector<std::string> &groups)
{
    int ret = SECURITY_MANAGER_SUCCESS;

    try {
        auto userType = m_cynaraAdmin.getUserType(uid);

        if (userType == SM_USER_TYPE_NONE) {
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        auto uidStr = std::to_string(uid);
        int result;
        std::string resultExtra;
        std::string bucket;

        switch (userType) {
            case SM_USER_TYPE_NORMAL:
                bucket = CynaraAdmin::Buckets.at(Bucket::USER_TYPE_NORMAL);
                break;
            case SM_USER_TYPE_ADMIN:
                bucket = CynaraAdmin::Buckets.at(Bucket::USER_TYPE_ADMIN);
                break;
            case SM_USER_TYPE_GUEST:
                bucket = CynaraAdmin::Buckets.at(Bucket::USER_TYPE_GUEST);
                break;
            case SM_USER_TYPE_SYSTEM:
                bucket = CynaraAdmin::Buckets.at(Bucket::USER_TYPE_SYSTEM);
                break;
            default:
                // Improperly configured
                return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        std::vector<std::pair<std::string, std::string>> group2privVector;
        m_privilegeDb.GetGroupsRelatedPrivileges(group2privVector);

        for (const auto &g2p : group2privVector) {
            m_cynaraAdmin.check(CYNARA_ADMIN_ANY, uidStr, g2p.second,
                                             bucket, result, resultExtra, true);
            if (result == CYNARA_ADMIN_ALLOW)
                groups.push_back(g2p.first);
        }
    } catch (const CynaraException::Base &e) {
        LogError("Error while getting user type from Cynara: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting groups from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return ret;
}

int ServiceImpl::appHasPrivilege(
        std::string appName,
        std::string privilege,
        uid_t uid,
        bool &result)
{
    try {
        std::string appProcessLabel = getAppProcessLabel(appName);
        std::string uidStr = std::to_string(uid);
        result = m_cynara.check(appProcessLabel, privilege, uidStr, "");
        LogDebug("result = " << result);
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::InvalidLabel &e) {
        LogError("Error while generating Smack labels: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    } catch (...) {
        LogError("Unknown exception thrown");
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }
    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::dropOnePrivateSharing(
        const std::string &ownerAppName,
        const std::string &ownerPkgName,
        const SmackRules::Labels &ownerPkgLabels,
        const std::string &targetAppName,
        const std::string &targetAppLabel,
        const std::string &path)
{
    int errorRet;
    try {
        int targetPathCount, pathCount, ownerTargetCount;
        m_privilegeDb.DropPrivateSharing(ownerAppName, targetAppName, path);
        m_privilegeDb.GetTargetPathSharingCount(targetAppName, path, targetPathCount);
        m_privilegeDb.GetPathSharingCount(path, pathCount);
        m_privilegeDb.GetOwnerTargetSharingCount(ownerAppName, targetAppName, ownerTargetCount);
        if (targetPathCount > 0) {
            return SECURITY_MANAGER_SUCCESS;
        }
        //This function can be also called when application is uninstalled, so path won't exist
        if (pathCount < 1 && fileExists(path)) {
            SmackLabels::setupPath(ownerPkgName, path, SECURITY_MANAGER_PATH_RW);
        }
        std::string pathLabel = SmackLabels::generateSharedPrivateLabel(ownerPkgName, path);
        SmackRules::dropPrivateSharingRules(ownerPkgName, ownerPkgLabels, targetAppLabel,
                                            pathLabel, pathCount < 1, ownerTargetCount < 1);
        return SECURITY_MANAGER_SUCCESS;
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while dropping private sharing in database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::Base &e) {
        LogError("Error performing smack operation: " << e.GetMessage());
        errorRet = SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const std::exception &e) {
        LogError("Some exception thrown : " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    } catch (...) {
        LogError("Unknown exception thrown");
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    }
    return errorRet;
}

int ServiceImpl::applyPrivatePathSharing(
        const Credentials &creds,
        const std::string &ownerAppName,
        const std::string &targetAppName,
        const std::vector<std::string> &paths)
{
    int errorRet;
    int sharingAdded = 0;
    std::string ownerPkgName;
    std::string targetPkgName;
    std::string targetAppLabel;
    SmackRules::Labels pkgsLabels;

    try {
        if (!authenticate(creds, Config::PRIVILEGE_APPSHARING_ADMIN)) {
            LogError("Caller is not permitted to manage file sharing");
            return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
        }

        m_privilegeDb.GetAppPkgName(ownerAppName, ownerPkgName);
        if (ownerPkgName.empty()) {
            LogError(ownerAppName << " is not an installed application");
            return SECURITY_MANAGER_ERROR_APP_UNKNOWN;
        }

        m_privilegeDb.GetAppPkgName(targetAppName, targetPkgName);
        if (targetPkgName.empty()) {
            LogError(targetAppName << " is not an installed application");
            return SECURITY_MANAGER_ERROR_APP_UNKNOWN;
        }

        for (const auto &path : paths) {
            std::string pathLabel = SmackLabels::getSmackLabelFromPath(path);
            if (pathLabel != SmackLabels::generatePathRWLabel(ownerPkgName)) {
                std::string generatedPathLabel = SmackLabels::generateSharedPrivateLabel(ownerPkgName, path);
                if (generatedPathLabel != pathLabel) {
                    LogError("Path " << path << " has label " << pathLabel << " and dosen't belong"
                             " to application " << ownerAppName);
                    return SECURITY_MANAGER_ERROR_APP_NOT_PATH_OWNER;
                }
            }
        }
        if (ownerAppName == targetAppName) {
            LogDebug("Owner application is the same as target application");
            return SECURITY_MANAGER_SUCCESS;
        }

        if (ownerPkgName == targetPkgName) {
            LogDebug("Owner and target belong to the same package");
            return SECURITY_MANAGER_SUCCESS;
        }
        targetAppLabel = getAppProcessLabel(targetAppName);
        getPkgLabels(ownerPkgName, pkgsLabels);

        ScopedTransaction trans(m_privilegeDb);
        for (const auto &path : paths) {
            int targetPathCount, pathCount, ownerTargetCount;
            m_privilegeDb.GetTargetPathSharingCount(targetAppName, path, targetPathCount);
            m_privilegeDb.GetPathSharingCount(path, pathCount);
            m_privilegeDb.GetOwnerTargetSharingCount(ownerAppName, targetAppName, ownerTargetCount);
            std::string pathLabel = SmackLabels::generateSharedPrivateLabel(ownerPkgName, path);
            m_privilegeDb.ApplyPrivateSharing(ownerAppName, targetAppName, path, pathLabel);
            sharingAdded++;
            if (targetPathCount > 0) {
                //Nothing to do, only counter needed incrementing
                continue;
            }
            if (pathCount <= 0) {
                SmackLabels::setupSharedPrivatePath(ownerPkgName, path);
            }
            SmackRules::applyPrivateSharingRules(ownerPkgName, pkgsLabels,
                    targetAppLabel, pathLabel, (pathCount > 0), (ownerTargetCount > 0));
        }
        trans.commit();
        return SECURITY_MANAGER_SUCCESS;
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while applying private sharing in database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::Base &e) {
        LogError("Error performing smack operation: " << e.GetMessage());
        errorRet = SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const std::exception &e) {
        LogError("Some exception thrown : " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    } catch (...) {
        LogError("Unknown exception thrown");
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    for (int i = 0; i < sharingAdded; i++) {
        const std::string &path = paths[i];
        dropOnePrivateSharing(ownerAppName, ownerPkgName, pkgsLabels,
                              targetAppName, targetAppLabel, path);
    }

    return errorRet;
}

int ServiceImpl::dropPrivatePathSharing(
        const Credentials &creds,
        const std::string &ownerAppName,
        const std::string &targetAppName,
        const std::vector<std::string> &paths)
{
    int errorRet;
    try {
        if (!authenticate(creds, Config::PRIVILEGE_APPSHARING_ADMIN)) {
            LogError("Caller is not permitted to manage file sharing");
            return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
        }

        std::string ownerPkgName;
        m_privilegeDb.GetAppPkgName(ownerAppName, ownerPkgName);
        if (ownerPkgName.empty()) {
            LogError(ownerAppName << " is not an installed application");
            return SECURITY_MANAGER_ERROR_APP_UNKNOWN;
        }

        std::string targetPkgName;
        m_privilegeDb.GetAppPkgName(targetAppName, targetPkgName);
        if (targetPkgName.empty()) {
            LogError(targetAppName << " is not an installed application");
            return SECURITY_MANAGER_ERROR_APP_UNKNOWN;
        }

        for (const auto &path : paths) {
            if (!sharingExists(targetAppName, path)) {
                LogError("Sharing doesn't exist: owner=" << ownerAppName
                         << ", target=" << targetAppName << ", path=" << path);
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
            }
            std::string pathLabel = SmackLabels::getSmackLabelFromPath(path);
            if (pathLabel != SmackLabels::generatePathRWLabel(ownerPkgName)) {
                std::string generatedPathLabel = SmackLabels::generateSharedPrivateLabel(ownerPkgName, path);
                if (generatedPathLabel != pathLabel) {
                    LogError("Path " << path << " has label " << pathLabel << " and dosen't belong"
                             " to application " << ownerAppName);
                    return SECURITY_MANAGER_ERROR_APP_NOT_PATH_OWNER;
                }
            }
        }

        if (ownerAppName == targetAppName) {
            LogDebug("Owner application is the same as target application");
            return SECURITY_MANAGER_SUCCESS;
        }

        if (ownerPkgName == targetPkgName) {
            LogDebug("Owner and target belong to the same package");
            return SECURITY_MANAGER_SUCCESS;
        }

        SmackRules::Labels pkgLabels;
        getPkgLabels(ownerPkgName, pkgLabels);
        auto targetAppLabel = getAppProcessLabel(targetAppName, targetPkgName);

        ScopedTransaction trans(m_privilegeDb);
        for (const auto &path : paths) {
            int ret = dropOnePrivateSharing(ownerAppName, ownerPkgName, pkgLabels,
                                            targetAppName, targetAppLabel, path);
            if (ret != SECURITY_MANAGER_SUCCESS) {
                return ret;
            }
        }
        trans.commit();
        return SECURITY_MANAGER_SUCCESS;
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while dropping private sharing in database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::Base &e) {
        LogError("Error performing smack operation: " << e.GetMessage());
        errorRet = SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const std::exception &e) {
        LogError("Some exception thrown : " << e.what());
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    } catch (...) {
        LogError("Unknown exception thrown");
        errorRet = SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    return errorRet;
}

int ServiceImpl::pathsRegister(const Credentials &creds, path_req req)
{
    LogDebug("Paths registration parameters: pkgName: " << req.pkgName <<
             ", uid: " << req.uid);

    if (req.pkgPaths.empty())
        return SECURITY_MANAGER_SUCCESS;

    setRequestDefaultValues(req.uid, req.installationType);

    try {
        if (!authCheck(creds, req.uid, req.installationType)) {
            LogError("Request from uid=" << creds.uid << ", Smack=" << creds.label <<
                " for path registration denied");
            return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;
        }
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    try {
        if (isSharedRO(req.pkgPaths)) {
            ScopedTransaction trans(m_privilegeDb);

            if (!m_privilegeDb.IsPackageSharedRO(req.pkgName)) {

                m_privilegeDb.SetSharedROPackage(req.pkgName);

                SmackRules::PkgsLabels pkgsLabels;

                std::vector<PkgInfo> pkgsInfo;
                m_privilegeDb.GetPackagesInfo(pkgsInfo);
                getPkgsProcessLabels(pkgsInfo, pkgsLabels);

                SmackRules::generateSharedRORules(pkgsLabels, pkgsInfo);
                SmackRules::mergeRules();
            }
            trans.commit();
        }
    } catch (const PrivilegeDb::Exception::IOError &e) {
        LogError("Cannot access application database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const PrivilegeDb::Exception::InternalError &e) {
        LogError("Error while saving application info to database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    return labelPaths(req.pkgPaths,
                      req.pkgName,
                      static_cast<app_install_type>(req.installationType),
                      req.uid);
}

int ServiceImpl::labelForProcess(const std::string &appName, std::string &label)
{
    LogDebug("Requested label generation for process of application " << appName);
    label = getAppProcessLabel(appName);

    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::shmAppName(const Credentials &creds, const std::string &shmName, const std::string &appName)
{
    try {
        if (shmName.empty() || appName.empty())
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;

        if (!PrivilegeDb::getInstance().AppNameExists(appName)) {
            LogError("Unknown application id: " << appName);
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        if (!authenticate(creds, Config::PRIVILEGE_SHM)) {
            LogError("Request from uid=" << creds.uid << ", Smack=" << creds.label << " for shm denied");
            return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;
        }

        std::string label = getAppProcessLabel(appName);

        int fd = shm_open(shmName.c_str(), O_RDWR, 0);
        if (fd < 0) {
            LogError("Error in shm_open");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        auto scopeClose = makeUnique(&fd, [](int *ptr) -> void { if (*ptr >= 0) close(*ptr);});

        Credentials fdCreds = Credentials::getCredentialsFromFd(fd);

        if (fdCreds.label == label) {
            // Nothing to do. The file already has proper label.
            // Client called this function twice?
            LogDebug("Noting to do. File have already label: " << label << " The client probably called this api twice.");
            return SECURITY_MANAGER_SUCCESS;
        }

        if ((creds.label != fdCreds.label) || (creds.uid != fdCreds.uid)) {
            LogDebug("Client (smack: " << creds.label <<", pid: " << creds.pid
                << ") does not have permission to access shared memory file (segment name: "
                << shmName << ").");
            return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
        }

        SmackLabels::setSmackLabelForFd(fd, label);
    } catch (const CynaraException::Base &e) {
        LogError("Error while querying Cynara for permissions: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const SmackException::Base &e) {
        LogError("Error while set/get smack label in /dev/shm: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        return SECURITY_MANAGER_ERROR_MEMORY;
    }
    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getAppDefinedPrivilegeProvider(uid_t uid, const std::string &privilege,
                                                std::string &appName, std::string &pkgName)
{
    std::string appNameString, pkgNameString, licenseString;
    try {
        // Get appName and License
        if (!m_privilegeDb.GetAppAndLicenseForAppDefinedPrivilege(uid, privilege, appNameString, licenseString) &&
            !m_privilegeDb.GetAppAndLicenseForAppDefinedPrivilege(getGlobalUserId(), privilege, appNameString, licenseString))
        {
            LogDebug("Privilege " << privilege << " not found in database");
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        // Convert appName to pkgName
        m_privilegeDb.GetAppPkgName(appNameString, pkgNameString);

        if (appNameString.empty() || pkgNameString.empty()) {
            LogWarning("Could not translate appName to pkgName. appName: " << appName);
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        LogDebug("Privilege: " << privilege << " provided by app: " << appNameString << " pkg: " << pkgNameString);
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting appName or pkgName from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    appName = appNameString;
    pkgName = pkgNameString;
    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getAppDefinedPrivilegeLicense(uid_t uid, const std::string &privilege,
                                                std::string &license)
{
    std::string appNameString, licenseString;
    try {
        if (!m_privilegeDb.GetAppAndLicenseForAppDefinedPrivilege(uid, privilege, appNameString, licenseString) &&
            !m_privilegeDb.GetAppAndLicenseForAppDefinedPrivilege(getGlobalUserId(), privilege, appNameString, licenseString))
        {
            LogDebug("Privilege " << privilege << " is not found in database");
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        if (licenseString.empty()) {
            LogWarning("Empty license was found in database for privlege: " << privilege);
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting license from database: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    license = licenseString;
    return SECURITY_MANAGER_SUCCESS;
}

int ServiceImpl::getClientPrivilegeLicense(const std::string &appName, uid_t uid, const std::string &privilege,
                                           std::string &license)
{
    std::string licenseString;
    try {
        uid_t requestUid = m_privilegeDb.IsUserAppInstalled(appName, uid) ? uid : getGlobalUserId();

        if (!m_privilegeDb.GetLicenseForClientPrivilege(appName, requestUid, privilege, licenseString)) {
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }
    } catch (const PrivilegeDb::Exception::Base &e) {
        LogError("Error while getting license for app: " << e.DumpToString());
        return SECURITY_MANAGER_ERROR_SERVER_ERROR;
    }

    license = licenseString;
    return SECURITY_MANAGER_SUCCESS;
}

} /* namespace SecurityManager */
