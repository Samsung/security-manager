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
 * @file        privilege_db.cpp
 * @author      Krzysztof Sasiak <k.sasiak@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     0.1
 * @brief       This file contains declaration of the API to privileges database.
 */

#include <cstdio>
#include <list>
#include <utility>
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
    } catch (DB::SqlConnection::Exception::ConstraintError &e) {
        LogError("Constraints violated by command: " << e.DumpToString());
        ThrowMsg(PrivilegeDb::Exception::ConstraintError,
            "Constraints violated by command: " << e.DumpToString());
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

bool PrivilegeDb::PkgNameExists(const std::string &pkgName)
{
    return try_catch<bool>([&] {
        auto command = getStatement(StmtType::EPkgNameExists);
        int cnt = 0;

        command->BindString(1, pkgName);
        if (command->Step())
            cnt = command->GetColumnInteger(0);

        LogDebug("PkgName " << pkgName  << " found in " << cnt << " entries in db");

        return (cnt > 0);
    });
}

bool PrivilegeDb::AppNameExists(const std::string &appName)
{
    return try_catch<bool>([&] {
        auto command = getStatement(StmtType::EAppNameExists);
        int cnt = 0;

        command->BindString(1, appName);
        if (command->Step())
            cnt = command->GetColumnInteger(0);

        LogDebug("AppName " << appName << " found in " << cnt << " entries in db");

        return (cnt > 0);
    });
}

void PrivilegeDb::GetAppPkgName(const std::string &appName, std::string &pkgName)
{
    return try_catch<void>([&] {
        pkgName.clear();

        auto command = getStatement(StmtType::EGetAppPkgName);
        command->BindString(1, appName);

        if (command->Step())
            pkgName = command->GetColumnString(0);
    });
}

void PrivilegeDb::GetAppVersion(const std::string &appName, std::string &tizenVer)
{
    return try_catch<void>([&] {
        tizenVer.clear();

        auto command = getStatement(StmtType::EGetAppVersion);
        command->BindString(1, appName);

        if (command->Step())
            tizenVer = command->GetColumnString(0);
    });
}

void PrivilegeDb::AddApplication(
        const std::string &appName,
        const std::string &pkgName,
        uid_t uid,
        const std::string &targetTizenVer,
        const std::string &authorName,
        bool isHybrid)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EAddApplication);
        command->BindString(1, appName);
        command->BindString(2, pkgName);
        command->BindInteger(3, static_cast<unsigned int>(uid));
        command->BindString(4, targetTizenVer);
        authorName.empty() ? command->BindNull(5) : command->BindString(5, authorName);
        command->BindInteger(6, isHybrid ? 1 : 0);

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                     Queries.at(StmtType::EAddApplication));
        };

        LogDebug("Added appName: " << appName << ", pkgName: " << pkgName);
    });
}

void PrivilegeDb::RemoveApplication(
        const std::string &appName,
        uid_t uid,
        bool &appNameIsNoMore,
        bool &pkgNameIsNoMore,
        bool &authorNameIsNoMore)
{
    try_catch<void>([&] {
        if (!AppNameExists(appName))
            return;

        std::string pkgName;
        GetAppPkgName(appName, pkgName);

        int authorId;
        GetPkgAuthorId(pkgName, authorId);

        auto command = getStatement(StmtType::ERemoveApplication);
        command->BindString(1, appName);
        command->BindInteger(2, static_cast<unsigned int>(uid));

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                    Queries.at(StmtType::ERemoveApplication));
        };

        LogDebug("Removed appName: " << appName);

        appNameIsNoMore = !(AppNameExists(appName));
        pkgNameIsNoMore = !(PkgNameExists(pkgName));
        authorNameIsNoMore = !(AuthorIdExists(authorId));
    });
}

void PrivilegeDb::GetPathSharingCount(const std::string &path, int &count)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetPathSharedCount);
        command->BindString(1, path);

        command->Step();
        count = command->GetColumnInteger(0);
    });
}

void PrivilegeDb::GetOwnerTargetSharingCount(const std::string &ownerAppName,
    const std::string &targetAppName, int &count)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetOwnerTargetSharedCount);
        command->BindString(1, ownerAppName);
        command->BindString(2, targetAppName);

        command->Step();
        count = command->GetColumnInteger(0);
    });
}

void PrivilegeDb::GetTargetPathSharingCount(const std::string &targetAppName,
    const std::string &path, int &count)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetTargetPathSharedCount);
        command->BindString(1, targetAppName);
        command->BindString(2, path);

        command->Step();
        count = command->GetColumnInteger(0);
    });
}

void PrivilegeDb::ApplyPrivateSharing(const std::string &ownerAppName,
    const std::string &targetAppName, const std::string &path,
    const std::string &pathLabel)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EAddPrivatePathSharing);
        command->BindString(1, ownerAppName);
        command->BindString(2, targetAppName);
        command->BindString(3, path);
        command->BindString(4, pathLabel);

        command->Step();
    });
}

void PrivilegeDb::DropPrivateSharing(const std::string &ownerAppName,
    const std::string &targetAppName, const std::string &path)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::ERemovePrivatePathSharing);
        command->BindString(1, ownerAppName);
        command->BindString(2, targetAppName);
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

void PrivilegeDb::GetPrivateSharingForOwner(const std::string &ownerAppName,
                                            std::map<std::string, std::vector<std::string>> &ownerSharing)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetSharingForOwner);
        command->BindString(1, ownerAppName);
        while (command->Step()) {
            std::string targetAppName = command->GetColumnString(0);
            std::string path = command->GetColumnString(1);
            LogDebug("Got appName : " << targetAppName << " and path label : " << path);
            ownerSharing[targetAppName].push_back(path);
        }
    });
}

void PrivilegeDb::GetPrivateSharingForTarget(const std::string &targetAppName,
                                             std::map<std::string, std::vector<std::string>> &targetSharing)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetSharingForTarget);
        command->BindString(1, targetAppName);
        while (command->Step()) {
            std::string ownerAppName = command->GetColumnString(0);
            std::string path = command->GetColumnString(1);
            LogDebug("Got appName : " << ownerAppName << " and path label : " << path);
            targetSharing[ownerAppName].push_back(path);
        }
    });
}

void PrivilegeDb::SquashSharing(const std::string &targetAppName, const std::string &path) {
    try_catch<void>([&] {
        auto command = getStatement(StmtType::ESquashSharing);
        command->BindString(1, targetAppName);
        command->BindString(2, path);

        command->Step();
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

void PrivilegeDb::GetUserPkgs(uid_t uid, std::vector<std::string> &pkgs)
{
   try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetUserPkgs);
        command->BindInteger(1, static_cast<unsigned int>(uid));
        pkgs.clear();
        while (command->Step()) {
            std::string pkg = command->GetColumnString(0);
            LogDebug("User " << uid << " has pkg " << pkg << " installed");
            pkgs.push_back(pkg);
        };
    });
}

void PrivilegeDb::GetAllPackages(std::vector<std::string> &packages)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetAllPackages);
        packages.clear();
        while (command->Step()) {
            const std::string &pkg = command->GetColumnString(0);
            LogDebug("Found " << pkg << " package installed");
            packages.push_back(pkg);
        };
     });
}

void PrivilegeDb::GetPkgApps(const std::string &pkgName,
        std::vector<std::string> &appNames)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetAppsInPkg);

        command->BindString(1, pkgName);
        appNames.clear();

        while (command->Step()) {
            std::string appName = command->GetColumnString(0);
            LogDebug("Got appName: " << appName << " for pkgName " << pkgName);
            appNames.push_back(appName);
        };
    });
}

void PrivilegeDb::GetPkgAuthorId(const std::string &pkgName, int &authorId)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetPkgAuthorId);

        command->BindString(1, pkgName);
        if (command->Step()) {
            authorId = command->GetColumnInteger(0);
            LogDebug("Got authorid: " << authorId << " for pkgName " << pkgName);
        } else {
            authorId = -1;
            LogDebug("No authorid found for pkgName " << pkgName);
        }
    });
}

void PrivilegeDb::GetAuthorIdByName(const std::string &authorName, int &authorId)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetAuthorIdByName);

        command->BindString(1, authorName);
        if (command->Step()) {
            authorId = command->GetColumnInteger(0);
            LogDebug("Got authorid: " << authorId << " for authorName " << authorName);
        } else {
            authorId = -1;
            LogDebug("No authorid found for authorName " << authorName);
        }
    });
}

bool PrivilegeDb::AuthorIdExists(int authorId)
{
    return try_catch<bool>([&]() -> bool {
        auto command = getStatement(StmtType::EAuthorIdExists);
        int cnt = 0;

        command->BindInteger(1, authorId);
        if (command->Step())
            cnt = command->GetColumnInteger(0);

        LogDebug("AuthorId " << authorId << " found in " << cnt << " entries in db");

        return (cnt > 0);
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

void PrivilegeDb::GetGroupsRelatedPrivileges(std::vector<std::pair<std::string, std::string>> &privileges)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetGroupsRelatedPrivileges);

        while (command->Step()) {
            const auto &groupName = command->GetColumnString(0);
            const auto &privName = command->GetColumnString(1);
            LogDebug("Privilege " << privName << " Group " << groupName);
            privileges.emplace_back(std::make_pair(groupName, privName));
        };
    });
}

void PrivilegeDb::SetSharedROPackage(const std::string &pkgName)
{
   try_catch<void>([&] {
        auto command = getStatement(StmtType::ESetPackageSharedRO);
        command->BindString(1, pkgName);

        if (command->Step())
            LogDebug("shared_ro has been set to 1 for pkg: " << pkgName);
    });
}

bool PrivilegeDb::IsPackageSharedRO(const std::string &pkgName)
{
   return try_catch<bool>([&]() -> bool {
        auto command = getStatement(StmtType::EIsPackageSharedRO);
        command->BindString(1, pkgName);
        int shared_ro = 0;

        if (command->Step())
            shared_ro = command->GetColumnInteger(0);

        LogDebug("Package " << pkgName << "has shared_ro set to " << shared_ro);

        return (shared_ro > 0);
    });
}

bool PrivilegeDb::IsPackageHybrid(const std::string& pkgName)
{
    return try_catch<bool>([&]() -> bool {
        auto command = getStatement(StmtType::EIsPackageHybrid);
        command->BindString(1, pkgName);
        int isHybrid = 0;

        if (command->Step())
            isHybrid = command->GetColumnInteger(0);

        LogDebug("Package " << pkgName << "has is_hybrid set to " << isHybrid);

        return (isHybrid > 0);
    });
}

void PrivilegeDb::GetPackagesInfo(std::vector<PkgInfo> &packages)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EGetPackagesInfo);
        packages.clear();
        while (command->Step()) {
            PkgInfo info;
            info.name = command->GetColumnString(0);
            info.sharedRO = command->GetColumnInteger(1) > 0;
            info.hybrid = command->GetColumnInteger(2) > 0;
            LogDebug("Found package info " << info.name << " shared ro: " <<
                     info.sharedRO << " hybrid: " << info.hybrid);
            packages.push_back(info);
        };
     });
}

void PrivilegeDb::AddAppDefinedPrivilege(const std::string &appName, uid_t uid,
                                         const AppDefinedPrivilege &privilege)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EAddAppDefinedPrivilege);
        command->BindString(1, appName);
        command->BindInteger(2, uid);
        command->BindString(3, std::get<0>(privilege));
        command->BindInteger(4, std::get<1>(privilege));
        command->BindString(5, std::get<2>(privilege));

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                     Queries.at(StmtType::EAddAppDefinedPrivilege));
        }

        LogDebug("Added privilege: " << std::get<0>(privilege) << " defined by: " << appName <<
                 " and user: " << uid);
     });
}

void PrivilegeDb::AddAppDefinedPrivileges(const std::string &appName, uid_t uid,
                                          const AppDefinedPrivilegesVector &privileges)
{
    for (const auto &privilege : privileges)
        AddAppDefinedPrivilege(appName, uid, privilege);
}

void PrivilegeDb::AddClientPrivilege(const std::string &appName, uid_t uid, const std::string &privilege,
                                     const std::string &license)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::EAddClientPrivilege);
        command->BindString(1, appName);
        command->BindInteger(2, uid);
        command->BindString(3, privilege);
        command->BindString(4, license);

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                     Queries.at(StmtType::EAddClientPrivilege));
        }

        LogDebug("Added privilege: " << privilege << " license: " << license <<
                 "defined by: " << appName << " and user: " << uid);
     });
}

void PrivilegeDb::RemoveAppDefinedPrivileges(const std::string &appName, uid_t uid)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::ERemoveAppDefinedPrivileges);
        command->BindString(1, appName);
        command->BindInteger(2, uid);

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                     Queries.at(StmtType::ERemoveAppDefinedPrivileges));
        };

        LogDebug("Removed privileges defined by: " << appName << " and user: " << uid);
     });
}

void PrivilegeDb::RemoveClientPrivileges(const std::string &appName, uid_t uid)
{
    try_catch<void>([&] {
        auto command = getStatement(StmtType::ERemoveClientPrivileges);
        command->BindString(1, appName);
        command->BindInteger(2, uid);

        if (command->Step()) {
            LogDebug("Unexpected SQLITE_ROW answer to query: " <<
                     Queries.at(StmtType::ERemoveClientPrivileges));
        };

        LogDebug("Removed privileges used by: " << appName << " and user: " << uid);
     });
}

void PrivilegeDb::GetAppDefinedPrivileges(const std::string &appName, uid_t uid,
                                          AppDefinedPrivilegesVector &privileges)
{
    try_catch<void>([&] {
        privileges.clear();

        auto command = getStatement(StmtType::EGetAppDefinedPrivileges);
        command->BindString(1, appName);
        command->BindInteger(2, uid);
        while (command->Step()) {
            auto privilege = command->GetColumnString(0);
            auto type = command->GetColumnInteger(1);
            auto license = command->GetColumnString(2);
            LogDebug("App: " << appName << " installed by: " << uid << " defines privilege: " << privilege);
            privileges.push_back(std::make_tuple<>(privilege, type, license));
        }
    });
}

bool PrivilegeDb::GetAppPkgLicenseForAppDefinedPrivilege(
        uid_t uid,
        const std::string &privilege,
        std::string &appName,
        std::string &pkgName,
        std::string &license)
{
    return try_catch<bool>([&] {
        appName.clear();
        pkgName.clear();
        license.clear();

        auto command = getStatement(StmtType::EGetAppPkgLicenseForAppDefinedPrivilege);
        command->BindInteger(1, uid);
        command->BindString(2, privilege);

        if (command->Step()) {
            appName = command->GetColumnString(0);
            pkgName = command->GetColumnString(1);
            license = command->GetColumnString(2);
            LogDebug("Privilege: " << privilege << " defined by " << appName << " " << pkgName);
            return true;
        }

        LogDebug("Privilege: " << privilege << " not exist");
        return false;
    });
}

bool PrivilegeDb::GetLicenseForClientPrivilegeAndApp(
        const std::string &appName,
        uid_t uid,
        const std::string &privilege,
        std::string &license)
{
    return try_catch<bool>([&] {
        license.clear();

        auto command = getStatement(StmtType::EGetLicenseForClientPrivilegeAndApp);
        command->BindString(1, appName);
        command->BindInteger(2, uid);
        command->BindString(3, privilege);

        if (command->Step()) {
            license = command->GetColumnString(0);
            LogDebug("License found for app: " << appName << " privilege: " <<
                privilege << " uid: " << uid << " License: " << license);
            return true;
        }

        LogDebug("License not found for app: " << appName << " privilege: " <<
            privilege << " uid: " << uid);
        return false;
    });
}

bool PrivilegeDb::GetLicenseForClientPrivilegeAndPkg(
        const std::string &pkgName,
        uid_t uid,
        const std::string &privilege,
        std::string &license)
{
    return try_catch<bool>([&] {
        license.clear();

        auto command = getStatement(StmtType::EGetLicenseForClientPrivilegeAndPkg);
        command->BindString(1, pkgName);
        command->BindInteger(2, uid);
        command->BindString(3, privilege);

        if (command->Step()) {
            license = command->GetColumnString(0);
            LogDebug("License found for pkg: " << pkgName << " privilege: " <<
                privilege << " uid: " << uid << " License: " << license);
            return true;
        }

        LogDebug("License not found for pkg: " << pkgName << " privilege: " <<
            privilege << " uid: " << uid);
        return false;
    });
}

bool PrivilegeDb::IsUserPkgInstalled(const std::string& pkgName, uid_t uid)
{
    return try_catch<bool>([&]() -> bool {
        auto command = getStatement(StmtType::EIsUserPkgInstalled);
        command->BindString(1, pkgName);
        command->BindInteger(2, uid);
        int isInstalled = 0;

        if (command->Step())
            isInstalled = command->GetColumnInteger(0);

        return (isInstalled > 0);
    });
}

} //namespace SecurityManager
