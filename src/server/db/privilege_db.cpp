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
 * @author      Rafal Krypa <r.krypa@samsung.com>
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

namespace SecurityManager {

/* Common code for handling SqlConnection exceptions */
template <typename T>
T try_catch(const std::function<T()> &func)
{
    try {
        return func();
    } catch (DB::SqlConnection::Exception::SyntaxError &e) {
        LogError("Syntax error in command: " << e.DumpToString());
        ThrowMsg(PrivilegeDb::Exception::InternalError,
            "Syntax error in command: " << e.DumpToString());
    } catch (DB::SqlConnection::Exception::InternalError &e) {
        LogError("Mysterious internal error in SqlConnection class" << e.DumpToString());
        ThrowMsg(PrivilegeDb::Exception::InternalError,
            "Mysterious internal error in SqlConnection class: " << e.DumpToString());
    }
}

PrivilegeDb::PrivilegeDb(const std::string &path)
{
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

PrivilegeDb::~PrivilegeDb()
{
    delete mSqlConnection;
}

void PrivilegeDb::BeginTransaction(void)
{
    try_catch<void>([&] {
        mSqlConnection->BeginTransaction();
    });
}

void PrivilegeDb::CommitTransaction(void)
{
    try_catch<void>([&] {
        mSqlConnection->CommitTransaction();
    });
}

void PrivilegeDb::RollbackTransaction(void)
{
    try_catch<void>([&] {
        mSqlConnection->RollbackTransaction();
    });
}

bool PrivilegeDb::PkgIdExists(const std::string &pkgId)
{
    return try_catch<bool>([&] {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::EPkgIdExists));
        command->BindString(1, pkgId.c_str());
        if (command->Step()) {
            LogPedantic("PkgId: " << pkgId << " found in database");
            command->Reset();
            return true;
        };

        return false;
    });
}

void PrivilegeDb::AddApplication(const std::string &appId,
        const std::string &pkgId, bool &pkgIdIsNew)
{
    pkgIdIsNew = !(this->PkgIdExists(pkgId));

    try_catch<void>([&] {
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
    });
}

void PrivilegeDb::RemoveApplication(const std::string &appId,
        const std::string &pkgId, bool &pkgIdIsNoMore)
{
    try_catch<void>([&] {
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
    });
}

void PrivilegeDb::GetPkgPrivileges(const std::string &pkgId,
        TPrivilegesList &currentPrivileges)
{
    try_catch<void>([&] {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::EGetPkgPrivileges));
        command->BindString(1, pkgId.c_str());

        while (command->Step()) {
            std::string privilege = command->GetColumnString(0);
            LogPedantic ("Got privilege: "<< privilege);
            currentPrivileges.push_back(privilege);
        };
    });
}

void PrivilegeDb::UpdatePrivileges(const std::string &appId,
        const std::string &pkgId, const TPrivilegesList &privileges,
        TPrivilegesList &addedPrivileges,
        TPrivilegesList &removedPrivileges)
{
    try_catch<void>([&] {
        DB::SqlConnection::DataCommandAutoPtr command;
        TPrivilegesList curPrivileges = TPrivilegesList();
        GetPkgPrivileges(pkgId, curPrivileges);

        //Data compilation
        std::set<std::string> privilegesSet = std::set<
                std::string>(privileges.begin(), privileges.end());
        std::set<std::string> curPrivilegesSet = std::set<
                std::string>(curPrivileges.begin(), curPrivileges.end());

        std::list < std::string > tmpPrivileges = std::list < std::string
                > (privileges.begin(), privileges.end());
        tmpPrivileges.merge (std::list < std::string
                >(curPrivileges.begin(), curPrivileges.end()));
        tmpPrivileges.unique ();

        for (auto privilege : tmpPrivileges) {
            if ((SET_CONTAINS(privilegesSet, privilege)) && !(SET_CONTAINS(curPrivilegesSet, privilege))) {
                addedPrivileges.push_back(privilege);
            }
            if (!(SET_CONTAINS(privilegesSet, privilege)) && (SET_CONTAINS(curPrivilegesSet, privilege))) {
                removedPrivileges.push_back(privilege);
            }

        }

        //adding missing privileges
        for (auto addedPrivilege : addedPrivileges) {
            command = mSqlConnection->PrepareDataCommand(
                    Queries.at(QueryType::EAddAppPrivileges));
            command->BindString(1, appId.c_str());
            command->BindString(2, pkgId.c_str());
            command->BindString(3, addedPrivilege.c_str());

            if (command->Step())
                LogPedantic("Unexpected SQLITE_ROW answer to query: " <<
                        Queries.at(QueryType::EAddAppPrivileges));

            command->Reset();
            LogPedantic(
                    "Added appId: " << appId << ", pkgId: " << pkgId << ", privilege: " << addedPrivilege);

        }

        //removing unwanted privileges
        for (auto removedPrivilege : removedPrivileges) {
            command = mSqlConnection->PrepareDataCommand(
                    Queries.at(QueryType::ERemoveAppPrivileges));
            command->BindString(1, appId.c_str());
            command->BindString(2, pkgId.c_str());
            command->BindString(3, removedPrivilege.c_str());

            if (command->Step())
                LogPedantic("Unexpected SQLITE_ROW answer to query: " <<
                        Queries.at(QueryType::EAddAppPrivileges));

            LogPedantic(
                    "Removed appId: " << appId << ", pkgId: " << pkgId << ", privilege: " << removedPrivilege);
        }
    });
}
} //namespace SecurityManager
