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

bool PrivilegeDb::AppIdExists(const std::string &appId)
{
    return try_catch<bool>([&] {
        auto command = getStatement(StmtType::EAppIdExists);
        command->BindString(1, appId);
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

bool PrivilegeDb::GetAppPkgIdAndVer(const std::string &appId, std::string &pkgId, std::string &tizenVer)
{
    return try_catch<bool>([&] {
        auto command = getStatement(StmtType::EGetPkgIdAndVer);
        command->BindString(1, appId);

        if (!command->Step()) {
            // No application with such appId
            return false;
        }

        // application package found in the database, get it
        pkgId = command->GetColumnString(0);
        tizenVer = command->GetColumnString(1);

        return true;
    });
}

void PrivilegeDb::AddApplication(
        const std::string &appId,
        const std::string &pkgId,
        uid_t uid,
        const std::string &targetTizenVer,
        const std::string &authorId)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EAddApplication);
        command->BindString(1, appId);
        command->BindString(2, pkgId);
        command->BindInteger(3, static_cast<unsigned int>(uid));
        command->BindString(4, targetTizenVer);
        authorId.empty() ? command->BindNull(5) : command->BindString(5, authorId);

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                    Queries.at(StmtType::EAddApplication));
        };

        LogDebug("Added appId: " << appId << ", pkgId: " << pkgId);
    });
}

void PrivilegeDb::RemoveApplication(
        const std::string &appId,
        uid_t uid,
        bool &appIdIsNoMore,
        bool &pkgIdIsNoMore,
        bool &authorIdIsNoMore)
{
    try_catch<void>([&] {
        std::string pkgId;
        std::string authorId;
        if (!GetAppPkgId(appId, pkgId)) {
            pkgIdIsNoMore = false;
            return;
        }

        authorIdIsNoMore = false;
        GetAuthorIdForAppId(appId, authorId);

        auto command = getStatement(StmtType::ERemoveApplication);
        command->BindString(1, appId);
        command->BindInteger(2, static_cast<unsigned int>(uid));

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                    Queries.at(StmtType::ERemoveApplication));
        };

        LogDebug("Removed appId: " << appId);

        appIdIsNoMore = !(this->AppIdExists(appId));
        pkgIdIsNoMore = !(this->PkgIdExists(pkgId));

        if (!authorId.empty()) {
            authorIdIsNoMore = !(this->AuthorIdExists(authorId));
        }
    });
}

void PrivilegeDb::GetPathSharingCount(const std::string &path, int &count) {
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetPathSharedCount);
        command->BindString(1, path);

        command->Step();
        count = command->GetColumnInteger(0);
    });
}
void PrivilegeDb::GetOwnerTargetSharingCount(const std::string &ownerAppId, const std::string &targetAppId,
                                int &count)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetOwnerTargetSharedCount);
        command->BindString(1, ownerAppId);
        command->BindString(2, targetAppId);

        command->Step();
        count = command->GetColumnInteger(0);
    });
}
void PrivilegeDb::GetTargetPathSharingCount(const std::string &targetAppId,
                               const std::string &path,
                               int &count)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetTargetPathSharedCount);
        command->BindString(1, targetAppId);
        command->BindString(2, path);

        command->Step();
        count = command->GetColumnInteger(0);
    });
}
void PrivilegeDb::ApplyPrivateSharing(const std::string &ownerAppId, const std::string &targetAppId,
                         const std::string &path, const std::string &pathLabel)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EAddPrivatePathSharing);
        command->BindString(1, ownerAppId);
        command->BindString(2, targetAppId);
        command->BindString(3, path);
        command->BindString(4, pathLabel);

        command->Step();
    });
}

void PrivilegeDb::DropPrivateSharing(const std::string &ownerAppId, const std::string &targetAppId,
                            const std::string &path)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::ERemovePrivatePathSharing);
        command->BindString(1, ownerAppId);
        command->BindString(2, targetAppId);
        command->BindString(3, path);

        command->Step();
    });
}

void PrivilegeDb::GetAllPrivateSharing(std::map<std::string, std::vector<std::string>> &appPathMap) {
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetAllSharedPaths);
        while (command->Step()) {
            std::string appName = command->GetColumnString(0);
            std::string path = command->GetColumnString(1);
            LogDebug("Got appName : " << appName << " and path : " << path);
            appPathMap[appName].push_back(path);
        }
    });
}

void PrivilegeDb::ClearPrivateSharing() {
    try_catch<void>([&] {
        {
            auto command = getStatement(StmtType::EClearSharing);
            command->Step();
        }
        {
            auto command = getStatement(StmtType::EClearPrivatePaths);
            command->Step();
        }
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

void PrivilegeDb::GetTizen2XApps(const std::string& origApp, std::vector<std::string> &apps)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetAllTizen2XApps);
        command->BindString(1, origApp);
        apps.clear();
        while (command->Step()) {
            const std::string & tizen2XApp = command->GetColumnString(0);
            LogDebug("Found " << tizen2XApp << " Tizen 2.X apps installed");
            apps.push_back(tizen2XApp);
        };
     });
}

void PrivilegeDb::GetTizen2XAppsAndPackages(const std::string& origApp,
    std::vector<std::string> &apps, std::vector<std::string> &packages)
{
    try_catch<void>([&] {
        {
            auto command = getStatement(StmtType::EGetAllTizen2XApps);
            command->BindString(1, origApp);
            apps.clear();
            while (command->Step()) {
                const std::string & tizen2XApp = command->GetColumnString(0);
                LogDebug("Found " << tizen2XApp << " Tizen 2.X apps installed");
                apps.push_back(tizen2XApp);
            };
        }
        // grouping the packages below (can not use the statement above)
        {
            auto command = getStatement(StmtType::EGetAllTizen2XPackages);
            command->BindString(1, origApp);
            packages.clear();
            while (command->Step()) {
                const std::string & tizen2XPkg = command->GetColumnString(0);
                LogDebug("Found " << tizen2XPkg << " Tizen 2.X packages installed");
                packages.push_back(tizen2XPkg);
            };
        }
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

void PrivilegeDb::GetAuthorIdForAppId(const std::string &appId,
        std::string &authorId)
{
    try_catch<void>([&] {
        authorId.clear();
        auto command = getStatement(StmtType::EGetAuthorIdAppId);

        command->BindString(1, appId);
        if (command->Step()) {
            authorId = command->GetColumnString(0);
            LogDebug("Got authorid: " << authorId << " for appId " << appId);
        } else {
            LogDebug("No authorid found for appId " << appId);
        }
    });
}

bool PrivilegeDb::AuthorIdExists(const std::string &authorId) {
    return try_catch<bool>([&]() -> bool {
        int result = 0;

        if (authorId.empty())
            return false;

        auto command = getStatement(StmtType::EAuthorIdExists);

        command->BindInteger(1, std::atoi(authorId.c_str()));
        if (command->Step()) {
            result = command->GetColumnInteger(0);
        }
        LogDebug("For author: " << authorId << " found " << result << " rows");
        return result;
    });
}

void PrivilegeDb::GetGroups(std::vector<std::string> &groups)
{
   try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetGroups);

        while (command->Step()) {
            std::string groupName = command->GetColumnString(0);
            LogDebug("Group " << groupName);
            groups.push_back(groupName);
        };
    });
}

} //namespace SecurityManager
