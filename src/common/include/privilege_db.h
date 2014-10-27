/*
 * security-manager, database access
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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

enum class QueryType {
    EGetPkgPrivileges,
    EAddApplication,
    ERemoveApplication,
    EAddAppPrivileges,
    ERemoveAppPrivileges,
    EPkgIdExists,
    EGetPkgId,
    EGetPrivilegeGroups,
};

class PrivilegeDb {
    /**
     * PrivilegeDb database class
     */

private:
    SecurityManager::DB::SqlConnection *mSqlConnection;
    const std::map<QueryType, const char * const > Queries = {
        { QueryType::EGetPkgPrivileges, "SELECT DISTINCT privilege_name FROM app_privilege_view WHERE pkg_name=? AND uid=? ORDER BY privilege_name"},
        { QueryType::EAddApplication, "INSERT INTO app_pkg_view (app_name, pkg_name, uid) VALUES (?, ?, ?)" },
        { QueryType::ERemoveApplication, "DELETE FROM app_pkg_view WHERE app_name=? AND uid=?" },
        { QueryType::EAddAppPrivileges, "INSERT INTO app_privilege_view (app_name, uid, privilege_name) VALUES (?, ?, ?)" },
        { QueryType::ERemoveAppPrivileges, "DELETE FROM app_privilege_view WHERE app_name=? AND uid=?" },
        { QueryType::EPkgIdExists, "SELECT * FROM pkg WHERE name=?" },
        { QueryType::EGetPkgId, " SELECT pkg_name FROM app_pkg_view WHERE app_name = ?" },
        { QueryType::EGetPrivilegeGroups, " SELECT name FROM privilege_group_view WHERE privilege_name = ?" },
    };

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

    /**
     * Constructor
     * @exception DB::SqlConnection::Exception::IOError on problems with database access
     *
     */
    PrivilegeDb(const std::string &path = std::string(PRIVILEGE_DB_PATH));

    ~PrivilegeDb(void);

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
     * Add an application into the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param uid - user identifier for whom application is going to be installed
     * @param[out] pkgIdIsNew - return info if pkgId is new to the database
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void AddApplication(const std::string &appId, const std::string &pkgId,
            uid_t uid, bool &pkgIdIsNew);

    /**
     * Remove an application from the database
     *
     * @param appId - application identifier
     * @param uid - user identifier whose application is going to be uninstalled
     * @param[out] pkgIdIsNoMore - return info if pkgId is in the database
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void RemoveApplication(const std::string &appId, uid_t uid, bool &pkgIdIsNoMore);

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
     * Retrieve list of group ids assigned to a privilege
     *
     * @param privilege - privilege identifier
     * @param[out] grp_names - list of group names assigned to the privilege
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     */
    void GetPrivilegeGroups(const std::string &privilege,
        std::vector<std::string> &grp_names);

};

} //namespace SecurityManager

#endif // PRIVILEGE_DB_H_
