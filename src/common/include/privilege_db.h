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
    EPkgIdExists,
    EAppIdExists,
    EGetPkgId,
    EGetPkgIdAndVer,
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
    EGetAuthorIdAppId,
    ERemoveAuthors,
    EAuthorIdExists,
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
        { StmtType::EPkgIdExists, "SELECT * FROM pkg WHERE name=?" },
        { StmtType::EAppIdExists, "SELECT * FROM app WHERE name=?" },
        { StmtType::EGetPkgId, "SELECT pkg_name FROM app_pkg_view WHERE app_name = ?" },
        { StmtType::EGetPkgIdAndVer, "SELECT pkg_name, version FROM app_pkg_view WHERE app_name = ?" },
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
        { StmtType::EGetAllTizen2XPackages,  "SELECT DISTINCT pkg_name FROM app_pkg_view WHERE version LIKE '2.%%' AND app_name <> ?" },
        { StmtType::EGetAppsInPkg, " SELECT app_name FROM app_pkg_view WHERE pkg_name = ?" },
        { StmtType::EGetGroups, "SELECT DISTINCT group_name FROM privilege_group_view" },
        { StmtType::EGetAuthorIdAppId, "SELECT author_id FROM app_pkg_view WHERE app_name = ?"},
        { StmtType::ERemoveAuthors, "DELETE FROM author where author_id IN (SELECT author_id from author LEFT JOIN APP USING(author_id) where app_id is NULL)"},
        { StmtType::EAuthorIdExists, "SELECT count(*) FROM author where author_id=?"},
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

    /**
     * Check if appId is registered in database
     *
     * @param appId - package identifier
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @return true if appId exists in the database
     *
     */
    bool AppIdExists(const std::string &appId);

    /**
     * Check if pkgId is already registered in database
     *
     * @param pkgId - package identifier
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @return true if pkgId exists in the database
     *
     */
    bool PkgIdExists(const std::string &pkgId);

public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, IOError)
        DECLARE_EXCEPTION_TYPE(Base, InternalError)
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
     * Return package id associated with a given application id
     *
     * @param appId - application identifier
     * @param[out] pkgId - return application's pkgId
     * @return true is application exists, false otherwise
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    bool GetAppPkgId(const std::string &appId, std::string &pkgId);

    /**
     * Return package id and tizen version associated with a given application id
     *
     * @param appId - application identifier
     * @param[out] pkgId - return application's pkgId
     * @param[out] tizenVer - return application's target tizen version
     * @return true is application exists, false otherwise
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    bool GetAppPkgIdAndVer(const std::string &appId, std::string &pkgId, std::string &tizenVer);

    /**
     * Retrieve list of privileges assigned to a pkgId
     *
     * @param pkgId - package identifier
     * @param uid - user identifier for whom privileges will be retrieved
     * @param[out] currentPrivileges - list of current privileges assigned to pkgId
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetPkgPrivileges(const std::string &pkgId, uid_t uid,
            std::vector<std::string> &currentPrivilege);

    /**
     * Retrieve list of privileges assigned to an appId
     *
     * @param appId - application identifier
     * @param uid - user identifier for whom privileges will be retrieved
     * @param[out] currentPrivileges - list of current privileges assigned to appId
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetAppPrivileges(const std::string &appId, uid_t uid,
        std::vector<std::string> &currentPrivileges);

    /**
     * Add an application into the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param uid - user identifier for whom application is going to be installed
     * @param targetTizenVer - target tizen version for application
     * @param author - author identifier
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void AddApplication(
            const std::string &appId,
            const std::string &pkgId,
            uid_t uid,
            const std::string &targetTizenVer,
            const std::string &authorId);

    /**
     * Remove an application from the database
     *
     * @param appId - application identifier
     * @param uid - user identifier whose application is going to be uninstalled
     * @param[out] appIdIsNoMore - return info if appId is in the database
     * @param[out] pkgIdIsNoMore - return info if pkgId is in the database
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void RemoveApplication(const std::string &appId, uid_t uid,
        bool &appIdIsNoMore, bool &pkgIdIsNoMore);

    /**
     * Remove privileges assigned to application
     *
     * @param appId - application identifier
     * @param uid - user identifier for whom privileges will be removed
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void RemoveAppPrivileges(const std::string &appId, uid_t uid);

    /**
     * Update privileges assigned to application
     * To assure data integrity this method must be called inside db transaction.
     *
     * @param appId - application identifier
     * @param uid - user identifier for whom privileges will be updated
     * @param privileges - list of privileges to assign
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void UpdateAppPrivileges(const std::string &appId, uid_t uid,
            const std::vector<std::string> &privileges);

    /**
     * Get count of existing sharing of given path
     *
     * @param path - path name
     * @param[out] count - count of sharing
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetPathSharingCount(const std::string &path, int &count);

    /**
     * Get count of existing sharing between given applications
     *
     * @param ownerAppId - application identifier
     * @param targetAppId - application identifier
     * @param[out] count - count of sharing
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetOwnerTargetSharingCount(const std::string &ownerAppId, const std::string &targetAppId,
                                    int &count);

    /**
     * Get count of existing path sharing with target application
     *
     * @param targetAppId - application identifier
     * @param path - user identifier for whom privileges will be updated
     * @param[out] count - count of sharing
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetTargetPathSharingCount(const std::string &targetAppId,
                                   const std::string &path,
                                   int &count);

    /**
     * Add information about path sharing between owner application and target application
     *
     * @param ownerAppId - application identifier
     * @param targetAppId - application identifier
     * @param path - path name
     * @param pathLabel - label of path
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void ApplyPrivateSharing(const std::string &ownerAppId, const std::string &targetAppId,
                             const std::string &path, const std::string &pathLabel);

    /**
     * Remove information about path sharing between owner application and target application
     *
     * @param ownerAppId - application identifier
     * @param targetAppId - application identifier
     * @param path - path name
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void DropPrivateSharing(const std::string &ownerAppId, const std::string &targetAppId,
                            const std::string &path);

    /**
     * Get all shared paths mapped to application names
     *
     * @param appPathMap - map containing vectors of paths shared by applications mapped by name
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetAllPrivateSharing(std::map<std::string, std::vector<std::string>> &appPathMap);

    /**
     * Clear information about private sharing.
     *
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void ClearPrivateSharing();

    /**
     * Retrieve list of group ids assigned to a privilege
     *
     * @param privilege - privilege identifier
     * @param[out] grp_names - list of group names assigned to the privilege
     * @exception DB::SqlConnection::Exception::InternalError on internal error
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
     */
    void GetUserApps(uid_t uid, std::vector<std::string> &apps);
    /**
     * Retrieve a list of all application ids for a package id
     *
     * @param pkgId - package id
     * @param[out] appIds - list of application ids for the package id
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetAppIdsForPkgId (const std::string &pkgId,
        std::vector<std::string> &appIds);
    /**
     * Retrieve list of all apps excluding one specified (typically action originator)
     *
     * @param origApp - do not include specific application name in the list
     * @param[out] apps - vector of appId describing installed 2.x apps,
     *                    this parameter do not need to be empty, but
     *                    it is being overwritten during function call.
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetTizen2XApps(const std::string& origApp, std::vector<std::string> &apps);

    /**
     * Retrieve list of all apps and packages excluding one specified (typically action originator)
     *
     * @param origApp - do not include specific application name in the list
     * @param[out] apps - vector of appId describing installed 2.x apps,
     *                    this parameter do not need to be empty, but
     *                    it is being overwritten during function call.
     * @param[out] packages - vector of pkgId describing installed 2.x packages,
     *                    this parameter do not need to be empty, but
     *                    it is being overwritten during function call.
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetTizen2XAppsAndPackages(const std::string& origApp,
         std::vector<std::string> &apps, std::vector<std::string> &packages);

    /* Retrive an id of an author from database
     *
     * @param appId - application id
     * @param[out] authorId - integer connected with author name
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetAuthorIdForAppId(const std::string &appId,
        std::string &authorId);

    void RemoveAuthor();
    void AuthorIdExists(const std::string &authorId, int &result);

    /**
     * Retrieve list of resource groups
     *
     * @param[out] grp_names - list of group names
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetGroups(std::vector<std::string> &grp_names);
};

} //namespace SecurityManager

#endif // PRIVILEGE_DB_H_
