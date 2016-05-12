/*
 * security-manager, database access
 *
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <cstdio>
#include <list>
#include <map>
#include <stdbool.h>
#include <string>

#include <dpl/db/sql_connection.h>
#include <tzplatform_config.h>

#ifndef PRIVILEGE_DB_H_
#define PRIVILEGE_DB_H_

namespace SecurityManager {

const char *const PRIVILEGE_DB_PATH = tzplatform_mkpath(TZ_SYS_DB, ".security-manager.db");

enum class StmtType {
    EGetPkgPrivileges,
    EGetAppPrivileges,
    EAddApplication,
    ERemoveApplication,
    EAddAppPrivileges,
    ERemoveAppPrivileges,
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
    EClearSharing,
    EClearPrivatePaths,
    EGetPrivilegeGroups,
    EGetUserApps,
    EGetAllTizen2XApps,
    EGetAllTizen2XPackages,
    EGetAppsInPkg,
    EGetGroups,
    EGetPkgAuthorId,
    EAuthorIdExists,
    EGetAuthorIdByName,
};

class PrivilegeDb {
    /**
     * PrivilegeDb database class
     */

private:
    /**
     * Constructor
     * @exception DB::SqlConnection::Exception::IOError on problems with database access
     *
     */
    PrivilegeDb(const std::string &path = std::string(PRIVILEGE_DB_PATH));

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
        { StmtType::EGetPkgPrivileges, "SELECT DISTINCT privilege_name FROM app_privilege_view WHERE pkg_name=? AND uid=? ORDER BY privilege_name"},
        { StmtType::EGetAppPrivileges, "SELECT DISTINCT privilege_name FROM app_privilege_view WHERE app_name=? AND uid=? ORDER BY privilege_name"},
        { StmtType::EAddApplication, "INSERT INTO app_pkg_view (app_name, pkg_name, uid, version, author_name) VALUES (?, ?, ?, ?, ?)" },
        { StmtType::ERemoveApplication, "DELETE FROM app_pkg_view WHERE app_name=? AND uid=?" },
        { StmtType::EAddAppPrivileges, "INSERT INTO app_privilege_view (app_name, uid, privilege_name) VALUES (?, ?, ?)" },
        { StmtType::ERemoveAppPrivileges, "DELETE FROM app_privilege_view WHERE app_name=? AND uid=?" },
        { StmtType::EPkgNameExists, "SELECT count(*) FROM pkg WHERE name=?" },
        { StmtType::EAppNameExists, "SELECT count(*) FROM app WHERE name=?" },
        { StmtType::EGetAppPkgName, "SELECT pkg_name FROM app_pkg_view WHERE app_name = ?" },
        { StmtType::EGetAppVersion, "SELECT version FROM app WHERE name = ?" },
        { StmtType::EGetPathSharedCount, "SELECT COUNT(*) FROM app_private_sharing_view WHERE path = ?"},
        { StmtType::EGetTargetPathSharedCount, "SELECT COUNT(*) FROM app_private_sharing_view WHERE target_app_name = ? AND path = ?"},
        { StmtType::EGetOwnerTargetSharedCount, "SELECT COUNT(*) FROM app_private_sharing_view WHERE owner_app_name = ? AND target_app_name = ?"},
        { StmtType::EAddPrivatePathSharing, "INSERT INTO app_private_sharing_view(owner_app_name, target_app_name, path, path_label) VALUES(?, ?, ?, ?)"},
        { StmtType::ERemovePrivatePathSharing, "DELETE FROM app_private_sharing_view WHERE owner_app_name = ? AND target_app_name = ? AND path = ?"},
        { StmtType::EGetAllSharedPaths, "SELECT owner_app_name, path FROM app_private_sharing_view ORDER BY owner_app_name"},
        { StmtType::EClearSharing, "DELETE FROM app_private_sharing;"},
        { StmtType::EClearPrivatePaths, "DELETE FROM shared_path;"},
        { StmtType::EGetPrivilegeGroups, " SELECT group_name FROM privilege_group_view WHERE privilege_name = ?" },
        { StmtType::EGetUserApps, "SELECT name FROM app WHERE uid=?" },
        { StmtType::EGetAllTizen2XApps,  "SELECT name FROM app WHERE version LIKE '2.%%' AND name <> ?" },
        { StmtType::EGetAllTizen2XPackages,  "SELECT DISTINCT pkg_name FROM app_pkg_view WHERE version LIKE '2.%%'" },
        { StmtType::EGetAppsInPkg, " SELECT app_name FROM app_pkg_view WHERE pkg_name = ?" },
        { StmtType::EGetGroups, "SELECT DISTINCT group_name FROM privilege_group_view" },
        { StmtType::EGetPkgAuthorId, "SELECT author_id FROM pkg WHERE name = ? AND author_id IS NOT NULL"},
        { StmtType::EAuthorIdExists, "SELECT count(*) FROM author where author_id=?"},
        { StmtType::EGetAuthorIdByName, "SELECT author_id FROM author WHERE name=?"},
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

    static PrivilegeDb &getInstance();

    /**
     * Begin transaction
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     *
     */
    void BeginTransaction(void);

    /**
     * Commit transaction
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     *
     */
    void CommitTransaction(void);

    /**
     * Rollback transaction
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     *
     */
    void RollbackTransaction(void);

    /**
     * Check if appName is registered in database
     *
     * @param appName - package identifier
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     *
     */
    bool AppNameExists(const std::string &appName);

    /**
     * Check if pkgName is already registered in database
     *
     * @param pkgName - package identifier
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     * @return true if pkgName exists in the database
     *
     */
    bool PkgNameExists(const std::string &pkgName);

    /**
     * Check if authorId is already registered in database
     *
     * @param authorId numerical author identifier
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     * @return true if authorId exists in the database
     *
     */
    bool AuthorIdExists(int authorId);

    /**
     * Return package id associated with a given application id
     *
     * @param appName - application identifier
     * @param[out] pkgName - return application's package identifier
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetAppPkgName(const std::string &appName, std::string &pkgName);

    /**
     * Return Tizen version associated with a given application identifier
     *
     * @param appName - application identifier
     * @param[out] tizenVer - return application's target Tizen version
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetAppVersion(const std::string &appName, std::string &tizenVer);

    /**
     * Retrieve list of privileges assigned to a package
     *
     * @param pkgName - package identifier
     * @param uid - user identifier for whom privileges will be retrieved
     * @param[out] currentPrivileges - list of current privileges assigned to the package
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetPkgPrivileges(const std::string &pkgName, uid_t uid,
            std::vector<std::string> &currentPrivilege);

    /**
     * Retrieve list of privileges assigned to an appName
     *
     * @param appName - application identifier
     * @param uid - user identifier for whom privileges will be retrieved
     * @param[out] currentPrivileges - list of current privileges assigned to appName
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetAppPrivileges(const std::string &appName, uid_t uid,
        std::vector<std::string> &currentPrivileges);

    /**
     * Add an application into the database
     *
     * @param appName - application identifier
     * @param pkgName - package identifier
     * @param uid - user identifier for whom application is going to be installed
     * @param targetTizenVer - target tizen version for application
     * @param author - author identifier
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void AddApplication(
            const std::string &appName,
            const std::string &pkgName,
            uid_t uid,
            const std::string &targetTizenVer,
            const std::string &authorId);

    /**
     * Remove an application from the database
     *
     * @param appName - application identifier
     * @param uid - user identifier whose application is going to be uninstalled
     * @param[out] appNameIsNoMore - return info if appName is in the database
     * @param[out] pkgNameIsNoMore - return info if pkgName is in the database
     * @param[out] authorNameIsNoMore - return info if authorName is in the database
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void RemoveApplication(
            const std::string &appName,
            uid_t uid,
            bool &appNameIsNoMore,
            bool &pkgNameIsNoMore,
            bool &authorNameIsNoMore);

    /**
     * Remove privileges assigned to application
     *
     * @param appName - application identifier
     * @param uid - user identifier for whom privileges will be removed
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void RemoveAppPrivileges(const std::string &appName, uid_t uid);

    /**
     * Update privileges assigned to application
     * To assure data integrity this method must be called inside db transaction.
     *
     * @param appName - application identifier
     * @param uid - user identifier for whom privileges will be updated
     * @param privileges - list of privileges to assign
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void UpdateAppPrivileges(const std::string &appName, uid_t uid,
            const std::vector<std::string> &privileges);

    /**
     * Get count of existing sharing of given path
     *
     * @param path - path name
     * @param[out] count - count of sharing
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetPathSharingCount(const std::string &path, int &count);

    /**
     * Get count of existing sharing between given applications
     *
     * @param ownerAppName - application identifier
     * @param targetAppName - application identifier
     * @param[out] count - count of sharing
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetOwnerTargetSharingCount(const std::string &ownerAppName, const std::string &targetAppName,
                                    int &count);

    /**
     * Get count of existing path sharing with target application
     *
     * @param targetAppName - application identifier
     * @param path - user identifier for whom privileges will be updated
     * @param[out] count - count of sharing
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
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
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void ApplyPrivateSharing(const std::string &ownerAppName, const std::string &targetAppName,
                             const std::string &path, const std::string &pathLabel);

    /**
     * Remove information about path sharing between owner application and target application
     *
     * @param ownerAppName - application identifier
     * @param targetAppName - application identifier
     * @param path - path name
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void DropPrivateSharing(const std::string &ownerAppName, const std::string &targetAppName,
                            const std::string &path);

    /**
     * Get all shared paths mapped to application names
     *
     * @param appPathMap - map containing vectors of paths shared by applications mapped by name
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetAllPrivateSharing(std::map<std::string, std::vector<std::string>> &appPathMap);

    /**
     * Clear information about private sharing.
     *
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void ClearPrivateSharing();

    /**
     * Retrieve list of group ids assigned to a privilege
     *
     * @param privilege - privilege identifier
     * @param[out] grp_names - list of group names assigned to the privilege
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
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
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetUserApps(uid_t uid, std::vector<std::string> &apps);

    /**
     * Retrieve a list of all application ids for a package id
     *
     * @param pkgName - package identifier
     * @param[out] appNames - list of application identifiers for the package
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetPkgApps(const std::string &pkgName, std::vector<std::string> &appNames);

    /**
     * Retrieve list of all apps excluding one specified (typically action originator)
     *
     * @param origApp - do not include specific application name in the list
     * @param[out] apps - vector of application identifiers describing installed 2.x apps,
     *                    this parameter do not need to be empty, but
     *                    it is being overwritten during function call.
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetTizen2XApps(const std::string &origApp, std::vector<std::string> &apps);

    /**
     * Retrieve list of all Tizen 2.X packages
     *
     * @param[out] packages - vector of package identifiers describing installed 2.x packages,
     *                    this parameter do not need to be empty, but
     *                    it is being overwritten during function call.
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetTizen2XPackages(std::vector<std::string> &packages);

    /* Retrive an id of an author from database
     *
     * @param pkgName[in] package identifier
     * @param authorId[out] author id associated with the package, or -1 if no
     *                      author was assigned during installation
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetPkgAuthorId(const std::string &pkgName, int &authorId);

    /* Retrieve an id of an author from database by its name
     *
     * @param[in] authorName    author's name
     * @param[out] authorId     matching author id or -1 if no such author exists
     *
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetAuthorIdByName(const std::string &authorName, int &authorId);

    /**
     * Retrieve list of resource groups
     *
     * @param[out] grp_names - list of group names
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @exception DB::SqlConnection::Exception::ConstraintError on constraint violation
     */
    void GetGroups(std::vector<std::string> &grp_names);
};

} //namespace SecurityManager

#endif // PRIVILEGE_DB_H_
