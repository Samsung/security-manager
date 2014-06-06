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
 * @file        privilege_db.cpp
 * @author      Krzysztof Sasiak <k.sasiak@samsung.com>
 * @version     0.1
 * @brief       This file contains declaration of the API to privileges database.
 */

#include <cstdio>
#include <set>
#include <list>
#include <string>
#include <iostream>

#include <dpl/log/log.h>
#include "privilege_db.h"

#define SET_CONTAINS(set,value) set.find(value)!=set.end()
#define CATCH_STANDARD_EXCEPTIONS  \
    catch (DB::SqlConnection::Exception::SyntaxError &e) { \
        LogDebug("Syntax error in command: " << e.DumpToString()); \
        ThrowMsg(PrivilegeDb::Exception::InternalError, \
            "Syntax error in command: " << e.DumpToString()); \
    } catch (DB::SqlConnection::Exception::InternalError &e) { \
        LogDebug("Mysterious internal error in SqlConnection class" << e.DumpToString()); \
        ThrowMsg(PrivilegeDb::Exception::InternalError, \
            "Mysterious internal error in SqlConnection class: " << e.DumpToString()); \
    }

namespace SecurityManager {

PrivilegeDb::PrivilegeDb(const std::string &path) {
    try {
        mSqlConnection = new DB::SqlConnection(path,
                DB::SqlConnection::Flag::None,
                DB::SqlConnection::Flag::RW);
    } catch (DB::SqlConnection::Exception::Base &e) {
        LogError("Database initialization error: " << e.DumpToString());
        ThrowMsg(PrivilegeDb::Exception::IOError,
                "Database initialization error:" << e.DumpToString());

    };
}

PrivilegeDb::~PrivilegeDb() {
    delete mSqlConnection;
}
;

void PrivilegeDb::BeginTransaction(void) {
    try {
        mSqlConnection->BeginTransaction();
    }CATCH_STANDARD_EXCEPTIONS;
}

void PrivilegeDb::CommitTransaction(void) {
    try {
        mSqlConnection->CommitTransaction();
    }CATCH_STANDARD_EXCEPTIONS;
}

void PrivilegeDb::RollbackTransaction(void) {
    try {
        mSqlConnection->RollbackTransaction();
    }CATCH_STANDARD_EXCEPTIONS;
}

bool PrivilegeDb::PkgIdExists(const std::string &pkgId) {

    try {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::EPkgIdExists));
        command->BindString(1, pkgId.c_str());
        if (command->Step()) {
            LogPedantic("PkgId: " << pkgId << " found in database");
            command->Reset();
            return true;
        };

    }CATCH_STANDARD_EXCEPTIONS;

    return false;
}

bool PrivilegeDb::AddApplication(const std::string &appId,
        const std::string &pkgId, bool &pkgIdIsNew) {

    pkgIdIsNew = !(this->PkgIdExists(pkgId));

    try {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::EAddApplication));

        command->BindString(1, appId.c_str());
        command->BindString(2, pkgId.c_str());

        if (command->Step()) {
            LogPedantic("Unexpected SQLITE_ROW answer to query: " <<
                    Queries.at(QueryType::EAddApplication));
        };

        command->Reset();
        LogPedantic( "Added appId: " << appId << ", pkgId: " << pkgId);

        return true;

    }CATCH_STANDARD_EXCEPTIONS;
    return false;

}

bool PrivilegeDb::RemoveApplication(const std::string &appId,
        const std::string &pkgId, bool &pkgIdIsNoMore) {

    try {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::ERemoveApplication));

        command->BindString(1, appId.c_str());
        command->BindString(2, pkgId.c_str());

        if (command->Step()) {
            LogPedantic("Unexpected SQLITE_ROW answer to query: " <<
                    Queries.at(QueryType::ERemoveApplication));
        };

        command->Reset();
        LogPedantic( "Removed appId: " << appId << ", pkgId: " << pkgId);

        pkgIdIsNoMore = !(this->PkgIdExists(pkgId));

        return true;

    }CATCH_STANDARD_EXCEPTIONS;
    return false;

}

bool PrivilegeDb::GetPkgPermissions(const std::string &pkgId,
        TPermissionsList &currentPermissions) {
    try {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::EGetPkgPermissions));
        command->BindString(1, pkgId.c_str());

        while (command->Step()) {
            std::string permission = command->GetColumnString(0);
            LogPedantic ("Got permission: "<< permission);
            currentPermissions.push_back(permission);
        };

        return true;
    }CATCH_STANDARD_EXCEPTIONS;

    return false;

}

bool PrivilegeDb::UpdatePermissions(const std::string &appId,
        const std::string &pkgId, const TPermissionsList &permissions,
        TPermissionsList &addedPermissions,
        TPermissionsList &removedPermissions) {

    DB::SqlConnection::DataCommandAutoPtr command;

    TPermissionsList curPermissions = TPermissionsList();
    if (!this->GetPkgPermissions(pkgId, curPermissions))
        return false;

    try {
        //Data compilation
        std::set<std::string> permissionsSet = std::set<
                std::string>(permissions.begin(), permissions.end());
        std::set<std::string> curPermissionsSet = std::set<
                std::string>(curPermissions.begin(), curPermissions.end());

        std::list < std::string > tmpPermissions = std::list < std::string
                > (permissions.begin(), permissions.end());
        tmpPermissions.merge (std::list < std::string
                >(curPermissions.begin(), curPermissions.end()));
        tmpPermissions.unique ();

        for (auto permission : tmpPermissions) {
            if ((SET_CONTAINS(permissionsSet, permission)) && !(SET_CONTAINS(curPermissionsSet, permission))) {
                addedPermissions.push_back(permission);
            }
            if (!(SET_CONTAINS(permissionsSet, permission)) && (SET_CONTAINS(curPermissionsSet, permission))) {
                removedPermissions.push_back(permission);
            }

        }

        //adding missing permissions
        for (auto addedPermission : addedPermissions) {
            command = mSqlConnection->PrepareDataCommand(
                    Queries.at(QueryType::EAddAppPermissions));
            command->BindString(1, appId.c_str());
            command->BindString(2, pkgId.c_str());
            command->BindString(3, addedPermission.c_str());

            if (command->Step())
                LogPedantic("Unexpected SQLITE_ROW answer to query: " <<
                        Queries.at(QueryType::EAddAppPermissions));

            command->Reset();
            LogPedantic(
                    "Added appId: " << appId << ", pkgId: " << pkgId << ", permission: " << addedPermission);

        }

        //removing unwanted permissions
        for (auto removedPermission : removedPermissions) {
            command = mSqlConnection->PrepareDataCommand(
                    Queries.at(QueryType::ERemoveAppPermissions));
            command->BindString(1, appId.c_str());
            command->BindString(2, pkgId.c_str());
            command->BindString(3, removedPermission.c_str());

            if (command->Step())
                LogPedantic("Unexpected SQLITE_ROW answer to query: " <<
                        Queries.at(QueryType::EAddAppPermissions));

            LogPedantic(
                    "Removed appId: " << appId << ", pkgId: " << pkgId << ", permission: " << removedPermission);
        }

        return true;

    }CATCH_STANDARD_EXCEPTIONS;

    return false;
}
} //namespace SecurityManager
