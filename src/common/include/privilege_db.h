/*
 * security-manager, database access
 *
 * Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Rafal Krypa <r.krypa@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * @file        privilege_db.h
 * @author      Krzysztof Sasiak <k.sasiak@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @author      Aleksander Zdyb <a.zdyb@samsung.com>
 * @version     1.0
 * @brief       This file contains declaration of the API to privilges database.
 */

#pragma once

#include <cstdio>
#include <list>
#include <utility>
#include <map>
#include <stdbool.h>
#include <string>
#include <vector>

#include "dpl/db/sql_connection.h"
#include "tzplatform-config.h"
#include "security-manager-types.h"

#include "pkg-info.h"

namespace SecurityManager {

const std::string PRIVILEGE_DB_PATH = TizenPlatformConfig::makePath(TZ_SYS_DB, ".security-manager.db");

enum class StmtType {
    EAddApplication,
    ERemoveApplication,
    EPkgNameExists,
    EAppNameExists,
    EGetAppPkgName,
    EGetAppVersion,
    EGetPathSharedCount,
    EGetTargetPathSharedCount,
    EGetOwnerTargetSharedCount,
    EAddPrivatePathSharing,
    ERemovePrivatePathSharing,
    EGetAllSharedPaths,
    EGetSharingForOwner,
    EGetSharingForTarget,
    ESquashSharing,
    EClearSharing,
    EClearPrivatePaths,
    EGetPrivilegeGroups,
    EGetUserApps,
    EGetUserPkgs,
    EGetAllPackages,
    EGetAppsInPkg,
    EGetGroups,
    EGetGroupsRelatedPrivileges,
    EGetPkgAuthorId,
    EAuthorIdExists,
    EGetAuthorIdByName,
    ESetPackageSharedRO,
    EIsPackageSharedRO,
    EIsPackageHybrid,
    EGetPackagesInfo,
    EAddAppDefinedPrivilege,
    EAddClientPrivilege,
    ERemoveAppDefinedPrivileges,
    ERemoveClientPrivileges,
    EGetAppDefinedPrivileges,
    EGetAppPkgLicenseForAppDefinedPrivilege,
    EGetLicenseForClientPrivilegeAndApp,
    EGetLicenseForClientPrivilegeAndPkg,
    EIsUserPkgInstalled,
};

// privilege, app_defined_privilege_type, license
typedef std::tuple<std::string, int, std::string> AppDefinedPrivilege;
typedef std::vector<AppDefinedPrivilege> AppDefinedPrivilegesVector;

class PrivilegeDb {
    /**
     * PrivilegeDb database class
     */

private:
    /**
     * Wrapper for prepared statement, it will reset statement at destruction.
     */
    class StatementWrapper {
    public:
        StatementWrapper(DB::SqlConnection::DataCommandAutoPtr &ref);
        ~StatementWrapper();
        DB::SqlConnection::DataCommand* operator->();
    private:
        DB::SqlConnection::DataCommandAutoPtr &m_ref;
    };

    SecurityManager::DB::SqlConnection *mSqlConnection;
    const std::map<StmtType, const char * const > Queries = {
        { StmtType::EAddApplication, "INSERT INTO user_app_pkg_view (app_name, pkg_name, uid, version, author_name, is_hybrid)"
                                    " VALUES (?, ?, ?, ?, ?, ?)" },
        { StmtType::ERemoveApplication, "DELETE FROM user_app_pkg_view WHERE app_name=? AND uid=?" },
        { StmtType::EPkgNameExists, "SELECT count(*) FROM pkg WHERE name=?" },
        { StmtType::EAppNameExists, "SELECT count(*) FROM app WHERE name=?" },
        { StmtType::EGetAppPkgName, "SELECT pkg_name FROM user_app_pkg_view WHERE app_name = ?" },
        { StmtType::EGetAppVersion, "SELECT version FROM app WHERE name = ?" },
        { StmtType::EGetPathSharedCount, "SELECT COUNT(*) FROM app_private_sharing_view WHERE path = ?"},
        { StmtType::EGetTargetPathSharedCount, "SELECT COUNT(*) FROM app_private_sharing_view WHERE target_app_name = ? AND path = ?"},
        { StmtType::EGetOwnerTargetSharedCount, "SELECT COUNT(*) FROM app_private_sharing_view WHERE owner_app_name = ? AND target_app_name = ?"},
        { StmtType::EAddPrivatePathSharing, "INSERT INTO app_private_sharing_view(owner_app_name, target_app_name, path, path_label) VALUES(?, ?, ?, ?)"},
        { StmtType::ERemovePrivatePathSharing, "DELETE FROM app_private_sharing_view WHERE owner_app_name = ? AND target_app_name = ? AND path = ?"},
        { StmtType::EGetAllSharedPaths, "SELECT DISTINCT owner_app_name, path FROM app_private_sharing_view ORDER BY owner_app_name"},
        { StmtType::EGetSharingForOwner, "SELECT target_app_name, path FROM app_private_sharing_view WHERE owner_app_name = ?"},
        { StmtType::EGetSharingForTarget, "SELECT owner_app_name, path FROM app_private_sharing_view WHERE target_app_name = ?"},
        { StmtType::ESquashSharing, "UPDATE app_private_sharing_view SET counter = 1 WHERE target_app_name = ? AND path = ?"},
        { StmtType::EClearSharing, "DELETE FROM app_private_sharing;"},
        { StmtType::EClearPrivatePaths, "DELETE FROM shared_path;"},
        { StmtType::EGetPrivilegeGroups, " SELECT group_name FROM privilege_group WHERE privilege_name = ?" },
        { StmtType::EGetUserApps, "SELECT app_name FROM user_app_pkg_view WHERE uid=?" },
        { StmtType::EGetUserPkgs, "SELECT DISTINCT pkg_name FROM user_app_pkg_view WHERE uid=?" },
        { StmtType::EGetAllPackages,  "SELECT DISTINCT pkg_name FROM user_app_pkg_view" },
        { StmtType::EGetAppsInPkg, " SELECT app_name FROM user_app_pkg_view WHERE pkg_name = ?" },
        { StmtType::EGetGroups, "SELECT DISTINCT group_name FROM privilege_group" },
        { StmtType::EGetGroupsRelatedPrivileges, "SELECT DISTINCT group_name, privilege_name FROM privilege_group" },
        { StmtType::EGetPkgAuthorId, "SELECT author_id FROM pkg WHERE name = ? AND author_id IS NOT NULL"},
        { StmtType::EAuthorIdExists, "SELECT count(*) FROM author where author_id=?"},
        { StmtType::EGetAuthorIdByName, "SELECT author_id FROM author WHERE name=?"},
        { StmtType::ESetPackageSharedRO, "UPDATE pkg SET shared_ro=1 WHERE name=?"},
        { StmtType::EIsPackageSharedRO, "SELECT shared_ro FROM pkg WHERE name=?"},
        { StmtType::EIsPackageHybrid, "SELECT is_hybrid FROM pkg WHERE name=?"},
        { StmtType::EGetPackagesInfo, "SELECT name, shared_ro, is_hybrid FROM pkg"},
        { StmtType::EAddAppDefinedPrivilege, "INSERT INTO app_defined_privilege_view (app_name, uid, privilege, type, license) VALUES (?, ?, ?, ?, ?)"},
        { StmtType::EAddClientPrivilege, "INSERT INTO client_license_view (app_name, uid, privilege, license) VALUES (?, ?, ?, ?)"},
        { StmtType::ERemoveAppDefinedPrivileges, "DELETE FROM app_defined_privilege_view WHERE app_name = ? AND uid = ?"},
        { StmtType::ERemoveClientPrivileges, "DELETE FROM client_license_view WHERE app_name = ? AND uid = ?"},
        { StmtType::EGetAppDefinedPrivileges, "SELECT privilege, type, license FROM app_defined_privilege_view WHERE app_name = ? AND uid = ?"},
        { StmtType::EGetAppPkgLicenseForAppDefinedPrivilege, "SELECT app_name, pkg_name, license FROM app_defined_privilege_view WHERE uid = ? AND privilege = ?"},
        { StmtType::EGetLicenseForClientPrivilegeAndApp, "SELECT license FROM client_license_view WHERE app_name = ? AND uid = ? AND privilege = ? "},
        { StmtType::EGetLicenseForClientPrivilegeAndPkg, "SELECT license FROM client_license_view WHERE pkg_name = ? AND uid = ? AND privilege = ? "},
        { StmtType::EIsUserPkgInstalled, "SELECT count(*) FROM user_app_pkg_view WHERE pkg_name = ? AND uid = ?"},
    };

    /**
     * Container for initialized DataCommands, prepared for binding.
     */
    std::vector<DB::SqlConnection::DataCommandAutoPtr> m_commands;

    /**
     * Fills empty m_commands map with sql commands prepared for binding.
     *
     * Because the "sqlite3_prepare_v2" function takes many cpu cycles, the PrivilegeDb
     * is optimized to call it only once for one query type.
     * Designed to be used in the singleton contructor.
     */
    void initDataCommands();

    /**
     * Return wrapped prepared query for given query type.
     * The query will be reset after wrapper destruction.
     *
     * @param queryType query identifier
     * @return wrapped prepared query
     */
    StatementWrapper getStatement(StmtType queryType);

public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, IOError)
        DECLARE_EXCEPTION_TYPE(Base, InternalError)
        DECLARE_EXCEPTION_TYPE(Base, ConstraintError)
    };

    ~PrivilegeDb(void);
    /**
     * Constructor
     * @exception PrivilegeDb::Exception::IOError on problems with database access
     *
     */
    PrivilegeDb(const std::string &path = std::string(PRIVILEGE_DB_PATH));

    static PrivilegeDb &getInstance();

    /**
     * Begin transaction
     * @exception PrivilegeDb::Exception::InternalError on internal error
     *
     */
    void BeginTransaction(void);

    /**
     * Commit transaction
     * @exception PrivilegeDb::Exception::InternalError on internal error
     *
     */
    void CommitTransaction(void);

    /**
     * Rollback transaction
     * @exception PrivilegeDb::Exception::InternalError on internal error
     *
     */
    void RollbackTransaction(void);

    /**
     * Check if appName is registered in database
     *
     * @param appName - package identifier
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     *
     */
    bool AppNameExists(const std::string &appName);

    /**
     * Check if pkgName is already registered in database
     *
     * @param pkgName - package identifier
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     * @return true if pkgName exists in the database
     *
     */
    bool PkgNameExists(const std::string &pkgName);

    /**
     * Check if authorId is already registered in database
     *
     * @param authorId numerical author identifier
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     * @return true if authorId exists in the database
     *
     */
    bool AuthorIdExists(int authorId);

    /**
     * Return package id associated with a given application id
     *
     * @param appName - application identifier
     * @param[out] pkgName - return application's package identifier
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetAppPkgName(const std::string &appName, std::string &pkgName);

    /**
     * Return Tizen version associated with a given application identifier
     *
     * @param appName - application identifier
     * @param[out] tizenVer - return application's target Tizen version
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetAppVersion(const std::string &appName, std::string &tizenVer);

    /**
     * Add an application into the database
     *
     * @param appName - application identifier
     * @param pkgName - package identifier
     * @param uid - user identifier for whom application is going to be installed
     * @param targetTizenVer - target tizen version for application
     * @param author - author identifier
     * @param isHybrid - hybrid flag setting
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void AddApplication(
            const std::string &appName,
            const std::string &pkgName,
            uid_t uid,
            const std::string &targetTizenVer,
            const std::string &authorId,
            bool isHybrid);

    /**
     * Remove an application from the database
     *
     * @param appName - application identifier
     * @param uid - user identifier whose application is going to be uninstalled
     * @param[out] appNameIsNoMore - return info if appName is in the database
     * @param[out] pkgNameIsNoMore - return info if pkgName is in the database
     * @param[out] authorNameIsNoMore - return info if authorName is in the database
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void RemoveApplication(
            const std::string &appName,
            uid_t uid,
            bool &appNameIsNoMore,
            bool &pkgNameIsNoMore,
            bool &authorNameIsNoMore);

    /**
     * Get count of existing sharing of given path
     *
     * @param path - path name
     * @param[out] count - count of sharing
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetPathSharingCount(const std::string &path, int &count);

    /**
     * Get count of existing sharing between given applications
     *
     * @param ownerAppName - application identifier
     * @param targetAppName - application identifier
     * @param[out] count - count of sharing
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetOwnerTargetSharingCount(const std::string &ownerAppName, const std::string &targetAppName,
                                    int &count);

    /**
     * Get count of existing path sharing with target application
     *
     * @param targetAppName - application identifier
     * @param path - user identifier for whom privileges will be updated
     * @param[out] count - count of sharing
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetTargetPathSharingCount(const std::string &targetAppName,
                                   const std::string &path,
                                   int &count);

    /**
     * Add information about path sharing between owner application and target application
     *
     * @param ownerAppName - application identifier
     * @param targetAppName - application identifier
     * @param path - path name
     * @param pathLabel - label of path
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void ApplyPrivateSharing(const std::string &ownerAppName, const std::string &targetAppName,
                             const std::string &path, const std::string &pathLabel);

    /**
     * Remove information about path sharing between owner application and target application
     *
     * @param ownerAppName - application identifier
     * @param targetAppName - application identifier
     * @param path - path name
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void DropPrivateSharing(const std::string &ownerAppName, const std::string &targetAppName,
                            const std::string &path);

    /**
     * Get all shared paths mapped to application names
     *
     * @param appPathMap - map containing vectors of paths shared by applications mapped by name
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetAllPrivateSharing(std::map<std::string, std::vector<std::string>> &appPathMap);

    /**
     * Get all paths shared with target applications by specified owner application
     *
     * @param ownerAppName - owner of queried sharings
     * @param ownerSharing - map containing vectors of paths shared by specified application
     *                     mapped by target application names
     * @exception PrivilegeDb::Exception::InternalError on internal error
     */
    void GetPrivateSharingForOwner(const std::string &ownerAppName,
                                   std::map<std::string, std::vector<std::string>> &ownerSharing);
    /**
     * Get all paths shared with specified target application name
     *
     * @param targetAppName - target of queried sharings
     * @param targetSharing - map containing vectors of paths shared with specified application
     *                     mapped by owner application names
     * @exception PrivilegeDb::Exception::InternalError on internal error
     */
    void GetPrivateSharingForTarget(const std::string &targetAppName,
                                    std::map<std::string, std::vector<std::string>> &targetSharing);

    /**
     * Change sharing counter to 1.
     *
     * @param targetAppName - target application name
     * @param path - path name
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     */
    void SquashSharing(const std::string &targetAppName, const std::string &path);

    /**
     * Clear information about private sharing.
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void ClearPrivateSharing();

    /**
     * Retrieve list of group ids assigned to a privilege
     *
     * @param privilege - privilege identifier
     * @param[out] grp_names - list of group names assigned to the privilege
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetPrivilegeGroups(const std::string &privilege,
        std::vector<std::string> &grp_names);

    /**
     * Retrieve list of apps assigned to user
     *
     * @param uid - user identifier
     * @param[out] apps - list of apps assigned to user,
     *                    this parameter do not need to be empty, but
     *                    it is being overwritten during function call.
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetUserApps(uid_t uid, std::vector<std::string> &apps);

    /**
     * Retrieve list of apps assigned to user
     *
     * @param uid - user identifier
     * @param[out] pkgs - list of packages assigned to user,
     *                    this parameter do not need to be empty, but
     *                    it is being overwritten during function call.
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetUserPkgs(uid_t uid, std::vector<std::string> &pkgs);

/**
     * Retrieve a list of all application ids for a package id
     *
     * @param pkgName - package identifier
     * @param[out] appNames - list of application identifiers for the package
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetPkgApps(const std::string &pkgName, std::vector<std::string> &appNames);

    /**
     * Retrieve list of all packages
     *
     * @param[out] packages - vector of package identifiers describing installed packages,
     *                        this parameter do not need to be empty, but
     *                        it is being overwritten during function call.
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetAllPackages(std::vector<std::string> &packages);

    /* Retrive an id of an author from database
     *
     * @param pkgName[in] package identifier
     * @param authorId[out] author id associated with the package, or -1 if no
     *                      author was assigned during installation
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetPkgAuthorId(const std::string &pkgName, int &authorId);

    /* Retrieve an id of an author from database by its name
     *
     * @param[in] authorName    author's name
     * @param[out] authorId     matching author id or -1 if no such author exists
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetAuthorIdByName(const std::string &authorName, int &authorId);

    /**
     * Retrieve list of resource groups
     *
     * @param[out] grp_names - list of group names
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetGroups(std::vector<std::string> &grp_names);

    /**
     * Retrieve vector of pairs with group_name (1st value) and privilege_name (2nd value)
     *
     * @param[out] privileges - list of privileges
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetGroupsRelatedPrivileges(std::vector<std::pair<std::string, std::string>> &privileges);

    /**
     * Set shared_ro field to 1 in package given by name
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void SetSharedROPackage(const std::string& pkgName);

    /**
     * Check whether package has shared_ro field set to 1 in db
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    bool IsPackageSharedRO(const std::string& pkgName);

    /**
     * Check whether package has is_hybrid field set to 1 in db
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    bool IsPackageHybrid(const std::string& pkgName);

    /**
     * Retrieve list of packages with information about shared RO presence and package type
     *
     * @param[out] packages - vector of PackageInfo objects describing installed packages,
     *                        this parameter do not need to be empty, but
     *                        it is being overwritten during function call.
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetPackagesInfo(std::vector<PkgInfo> &packages);

    /**
     * Add new privilege and license defined by application
     *
     * @param[in] appName - application identifier
     * @param[in] uid - user identifier
     * @param[in] privilege - privilege identifier
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void AddAppDefinedPrivilege(const std::string &appName, uid_t uid, const AppDefinedPrivilege &privilege);

    /**
     * Add vector of privileges defined by application
     *
     * @param[in] appName - application identifier
     * @param[in] uid - user identifier
     * @param[in] privileges - list of privileges
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void AddAppDefinedPrivileges(const std::string &appName, uid_t uid, const AppDefinedPrivilegesVector &privileges);

    /**
     * Add privilege and license used by client application
     *
     * @param[in] appName - application identifier
     * @param[in] uid - user identifier
     * @param[in] privilege - privilege identifier
     * @param[in] license - license
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void AddClientPrivilege(const std::string &appName, uid_t uid, const std::string &privilege,
                            const std::string &license);

    /**
     * Remove privileges/licenses defined by application
     *
     * @param[in] appName - application identifier
     * @param[in] uid - user identifier
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void RemoveAppDefinedPrivileges(const std::string &appName, uid_t uid);

    /**
     * Remove privileges/licenses used by client application
     *
     * @param[in] appName - application identifier
     * @param[in] uid - user identifier
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void RemoveClientPrivileges(const std::string &appName, uid_t uid);

    /**
     * Retrieve vector of pairs with privilege (1st value) and privilege type (2nd value)
     *
     * @param[in]  appName - application identifier
     * @param[in]  uid - user identifier
     * @param[out] privileges - list of privileges
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    void GetAppDefinedPrivileges(const std::string &appName, uid_t uid, AppDefinedPrivilegesVector &privileges);

    /**
     * Retrieve application and license of application which define privilege
     *
     * @param[in]  uid - user identifier
     * @param[in]  privilege - privilege identifier
     * @param[out] appName - application identifier
     * @param[out] pkgName - application package
     * @param[out] license - verification factor required by license-manager
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     * @return true if data were found in the database
     */
    bool GetAppPkgLicenseForAppDefinedPrivilege(uid_t uid,
                                                const std::string &privilege,
                                                std::string &appName,
                                                std::string &pkgName,
                                                std::string &license);

    /**
     * Retrieve license of client application
     *
     * @param[in]  appName - application identifier
     * @param[in]  uid - user identifier
     * @param[in]  privilege - privilege identifier
     * @param[out] license - verification factor required by license-manager
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     * @return true if data were found in the database
     */
    bool GetLicenseForClientPrivilegeAndApp(const std::string &appName,
                                            uid_t uid,
                                            const std::string &privilege,
                                            std::string &license);
    /**
     * Retrieve license of client application
     *
     * @param[in]  pkgName - application package
     * @param[in]  uid - user identifier
     * @param[in]  privilege - privilege identifier
     * @param[out] license - verification factor required by license-manager
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     * @return true if data were found in the database
     */
    bool GetLicenseForClientPrivilegeAndPkg(const std::string &pkgName,
                                            uid_t uid,
                                            const std::string &privilege,
                                            std::string &license);


    /**
     * Check whether user has installed package
     *
     * @exception PrivilegeDb::Exception::InternalError on internal error
     * @exception PrivilegeDb::Exception::ConstraintError on constraint violation
     */
    bool IsUserPkgInstalled(const std::string& pkgName, uid_t uid);
};

} //namespace SecurityManager
