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
#include <list>
#include <string>
#include <iostream>

#include <dpl/log/log.h>
#include "privilege_db.h"

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
        initDataCommands();
    } catch (DB::SqlConnection::Exception::Base &e) {
        LogError("Database initialization error: " << e.DumpToString());
        ThrowMsg(PrivilegeDb::Exception::IOError,
                "Database initialization error:" << e.DumpToString());

    };
}

void PrivilegeDb::initDataCommands()
{
    for (auto &it : Queries) {
        m_commands.push_back(mSqlConnection->PrepareDataCommand(it.second));
    }
}

PrivilegeDb::StatementWrapper::StatementWrapper(DB::SqlConnection::DataCommandAutoPtr &ref)
    : m_ref(ref) {}

PrivilegeDb::StatementWrapper::~StatementWrapper()
{
    m_ref->Reset();
}

DB::SqlConnection::DataCommand* PrivilegeDb::StatementWrapper::operator->()
{
    return m_ref.get();
}

PrivilegeDb::StatementWrapper PrivilegeDb::getStatement(StmtType queryType)
{
    return StatementWrapper(m_commands.at(static_cast<size_t>(queryType)));
}

PrivilegeDb::~PrivilegeDb()
{
    m_commands.clear();
    delete mSqlConnection;
}

PrivilegeDb &PrivilegeDb::getInstance()
{
    static PrivilegeDb privilegeDb;
    return privilegeDb;
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
        auto command = getStatement(StmtType::EPkgIdExists);
        command->BindString(1, pkgId);
        return command->Step();
    });
}

bool PrivilegeDb::GetAppPkgId(const std::string &appId, std::string &pkgId)
{
    return try_catch<bool>([&] {
        auto command = getStatement(StmtType::EGetPkgId);
        command->BindString(1, appId);

        if (!command->Step()) {
            // No application with such appId
            return false;
        }

        // application package found in the database, get it
        pkgId = command->GetColumnString(0);

        return true;
    });
}

void PrivilegeDb::AddApplication(const std::string &appId,
        const std::string &pkgId, uid_t uid)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EAddApplication);
        command->BindString(1, appId);
        command->BindString(2, pkgId);
        command->BindInteger(3, static_cast<unsigned int>(uid));

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                    Queries.at(StmtType::EAddApplication));
        };

        LogDebug("Added appId: " << appId << ", pkgId: " << pkgId);
    });
}

void PrivilegeDb::RemoveApplication(const std::string &appId, uid_t uid,
        bool &pkgIdIsNoMore)
{
    try_catch<void>([&] {
        std::string pkgId;
        if (!GetAppPkgId(appId, pkgId)) {
            pkgIdIsNoMore = false;
            return;
        }

        auto command = getStatement(StmtType::ERemoveApplication);
        command->BindString(1, appId);
        command->BindInteger(2, static_cast<unsigned int>(uid));

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                    Queries.at(StmtType::ERemoveApplication));
        };

        LogDebug("Removed appId: " << appId);

        pkgIdIsNoMore = !(this->PkgIdExists(pkgId));
    });
}

void PrivilegeDb::GetPkgPrivileges(const std::string &pkgId, uid_t uid,
        std::vector<std::string> &currentPrivileges)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetPkgPrivileges);
        command->BindString(1, pkgId);
        command->BindInteger(2, static_cast<unsigned int>(uid));

        while (command->Step()) {
            std::string privilege = command->GetColumnString(0);
            LogDebug("Got privilege: " << privilege);
            currentPrivileges.push_back(privilege);
        };
    });
}

void PrivilegeDb::GetAppPrivileges(const std::string &appId, uid_t uid,
        std::vector<std::string> &currentPrivileges)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetAppPrivileges);

        command->BindString(1, appId);
        command->BindInteger(2, static_cast<unsigned int>(uid));
        currentPrivileges.clear();

        while (command->Step()) {
            std::string privilege = command->GetColumnString(0);
            LogDebug("Got privilege: " << privilege);
            currentPrivileges.push_back(privilege);
        };
    });
}

void PrivilegeDb::RemoveAppPrivileges(const std::string &appId, uid_t uid)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::ERemoveAppPrivileges);
        command->BindString(1, appId);
        command->BindInteger(2, static_cast<unsigned int>(uid));
        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                    Queries.at(StmtType::ERemoveAppPrivileges));
        }

        LogDebug("Removed all privileges for appId: " << appId);
    });
}

void PrivilegeDb::UpdateAppPrivileges(const std::string &appId, uid_t uid,
        const std::vector<std::string> &privileges)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EAddAppPrivileges);
        command->BindString(1, appId);
        command->BindInteger(2, static_cast<unsigned int>(uid));

        RemoveAppPrivileges(appId, uid);

        for (const auto &privilege : privileges) {
            command->BindString(3, privilege);
            command->Step();
            command->Reset();
            LogDebug("Added privilege: " << privilege << " to appId: " << appId);
        }
    });
}

void PrivilegeDb::GetPrivilegeGroups(const std::string &privilege,
        std::vector<std::string> &groups)
{
   try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetPrivilegeGroups);
        command->BindString(1, privilege);

        while (command->Step()) {
            std::string groupName = command->GetColumnString(0);
            LogDebug("Privilege " << privilege << " gives access to group: " << groupName);
            groups.push_back(groupName);
        };
    });
}

void PrivilegeDb::GetUserApps(uid_t uid, std::vector<std::string> &apps)
{
   try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetUserApps);
        command->BindInteger(1, static_cast<unsigned int>(uid));
        apps.clear();
        while (command->Step()) {
            std::string app = command->GetColumnString(0);
            LogDebug("User " << uid << " has app " << app << " installed");
            apps.push_back(app);
        };
    });
}

void PrivilegeDb::GetAppIdsForPkgId(const std::string &pkgId,
        std::vector<std::string> &appIds)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetAppsInPkg);

        command->BindString(1, pkgId);
        appIds.clear();

        while (command->Step()) {
            std::string appId = command->GetColumnString (0);
            LogDebug ("Got appid: " << appId << " for pkgId " << pkgId);
            appIds.push_back(appId);
        };
    });
}

void PrivilegeDb::GetDefaultMapping(const std::string &version_from,
                                    const std::string &version_to,
                                    std::vector<std::string> &mappings)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetDefaultMappings);
        command->BindString(1, version_from);
        command->BindString(2, version_to);

        mappings.clear();
        while (command->Step()) {
            std::string mapping = command->GetColumnString(0);
            LogDebug("Default Privilege from version " << version_from
                    <<" to version " << version_to << " is " << mapping);
            mappings.push_back(mapping);
        }
    });
}

void PrivilegeDb::GetPrivilegeMappings(const std::string &version_from,
                                       const std::string &version_to,
                                       const std::string &privilege,
                                       std::vector<std::string> &mappings)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetPrivilegeMappings);
        command->BindString(1, version_from);
        command->BindString(2, version_to);
        command->BindString(3, privilege);

        mappings.clear();
        while (command->Step()) {
            std::string mapping = command->GetColumnString(0);
            LogDebug("Privilege " << privilege << " in version " << version_from
                    <<" has mapping " << mapping << " in version " << version_to);
            mappings.push_back(mapping);
        }
    });
}

void PrivilegeDb::GetPrivilegesMappings(const std::string &version_from,
                                        const std::string &version_to,
                                        const std::vector<std::string> &privileges,
                                        std::vector<std::string> &mappings)
{
    try_catch<void>([&] {
        auto deleteCmd = getStatement(StmtType::EDeletePrivilegesToMap);
        deleteCmd->Step();

        auto insertCmd = getStatement(StmtType::EInsertPrivilegeToMap);
        for (auto &privilege : privileges) {
            if (privilege.empty())
                continue;
            insertCmd->BindString(1, privilege);
            insertCmd->Step();
            insertCmd->Reset();
        }

        insertCmd->BindNull(1);
        insertCmd->Step();

        auto queryCmd = getStatement(StmtType::EGetPrivilegesMappings);
        queryCmd->BindString(1, version_from);
        queryCmd->BindString(2, version_to);

        mappings.clear();
        while (queryCmd->Step()) {
            std::string mapping = queryCmd->GetColumnString(0);
            LogDebug("Privilege set  in version " << version_from
                     <<" has mapping " << mapping << " in version " << version_to);
             mappings.push_back(mapping);
        }
    });
}

} //namespace SecurityManager
