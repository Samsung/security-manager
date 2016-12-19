/*
 *  Copyright (c) 2016 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       privilege_db_fixture.h
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */
#include <string>
#include <sys/types.h>

#include "privilege_db.h"

#define PRIVILEGE_DB_TEMPLATE DB_TEST_DIR"/.security-manager-test.db"
#define PRIVILEGE_DB_JOURNAL_TEMPLATE DB_TEST_DIR"/.security-manager-test.db-journal"

#define TEST_PRIVILEGE_DB_PATH "/tmp/.security-manager-test.db"
#define TEST_PRIVILEGE_DB_JOURNAL_PATH "/tmp/.security-manager-test.db-journal"

using namespace SecurityManager;

struct PrivilegeDBFixture {
public:
    PrivilegeDBFixture();
    ~PrivilegeDBFixture();

    PrivilegeDb* getPrivDb();

    void addAppSuccess(const std::string &appName, const std::string &pkgName,
        const uid_t uid, const std::string &tizenVer, const std::string &authorName, bool isHybrid);
    void addAppFail(const std::string &appName, const std::string &pkgName,
        const uid_t uid, const std::string &tizenVer, const std::string &authorName, bool isHybrid);
    void removeApp(const std::string &appName, const uid_t uid, bool expAppNameIsNoMore,
        bool expPkgNameIsNoMore, bool expAuthorNameIsNoMore);
    void removeAppSuccess(const std::string &appName, const uid_t uid);
    void checkPrivateSharing(const std::string &ownerAppName,
        const std::string &targetAppName, const std::string &path, int expectedPathCount,
        int expectedOwnerTargetCount, int expectedTargetPathCount);

    static const bool Hybrid;
    static const bool NotHybrid;
    static std::string app(int i);
    static std::string pkg(int i);
    static std::string tizenVer(int i);
    static std::string author(int i);
    static std::string path(int i);
    static std::string lab(int i);
    static uid_t uid(uid_t i);

protected:
    PrivilegeDb *testPrivDb;
};
