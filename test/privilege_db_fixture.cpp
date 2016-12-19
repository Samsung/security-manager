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
 * @file       privilege_db_fixture.cpp
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */

#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <sys/types.h>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include "privilege_db.h"
#include "privilege_db_fixture.h"

using namespace SecurityManager;

static const uid_t FirstUidForTests = 9900;

static void putFile(const std::string &source, const std::string &destination)
{
    if (std::ifstream(destination))
        BOOST_WARN_MESSAGE(remove(destination.c_str()) == 0,
            "Could not delete file" << destination);
    std::ifstream src(source.c_str(), std::ios::binary);
    std::ofstream dst(destination.c_str(), std::ios::binary);
    dst << src.rdbuf();
    src.close();
    dst.close();
}

static std::string genName(const std::string &prefix, int i)
{
    std::string caseName(boost::unit_test::framework::current_test_case().p_name);
    return prefix + std::to_string(i) + "_" + caseName;
}


PrivilegeDBFixture::PrivilegeDBFixture()
{
    putFile(std::string(PRIVILEGE_DB_TEMPLATE), std::string(TEST_PRIVILEGE_DB_PATH));
    putFile(std::string(PRIVILEGE_DB_JOURNAL_TEMPLATE), std::string(TEST_PRIVILEGE_DB_JOURNAL_PATH));

    testPrivDb = new PrivilegeDb(TEST_PRIVILEGE_DB_PATH);
};

PrivilegeDBFixture::~PrivilegeDBFixture()
{
    if (std::ifstream(TEST_PRIVILEGE_DB_PATH))
        BOOST_WARN_MESSAGE(remove(TEST_PRIVILEGE_DB_PATH) == 0,
            "Could not delete test database file: " << TEST_PRIVILEGE_DB_PATH);
    if (std::ifstream(TEST_PRIVILEGE_DB_JOURNAL_PATH))
        BOOST_WARN_MESSAGE(remove(TEST_PRIVILEGE_DB_JOURNAL_PATH) == 0,
             "Could not delete test database file: " << TEST_PRIVILEGE_DB_JOURNAL_PATH);

    delete testPrivDb;
}

PrivilegeDb* PrivilegeDBFixture::getPrivDb() {
    return testPrivDb;
}

void PrivilegeDBFixture::addAppSuccess(const std::string &appName,
    const std::string &pkgName, const uid_t uid, const std::string &tizenVer,
    const std::string &authorName, bool isHybrid)
{
    int authorId;

    BOOST_REQUIRE_NO_THROW(testPrivDb->AddApplication(appName, pkgName, uid, tizenVer,
        authorName, isHybrid));

    BOOST_REQUIRE_MESSAGE(testPrivDb->AppNameExists(appName),
        "AppNameExists wrongly not reported " << appName << " as existing application name");
    BOOST_REQUIRE_MESSAGE(testPrivDb->PkgNameExists(pkgName),
        "PkgNameExists wrongly not reported " << pkgName << " as existing package name");

    if (authorName.length() > 0) {
        BOOST_REQUIRE_NO_THROW(testPrivDb->GetAuthorIdByName(authorName, authorId));
        BOOST_REQUIRE_MESSAGE(testPrivDb->AuthorIdExists(authorId),
            "AuthorIdExists wrongly not reported " << uid << " as existing author id");
    }
}

void PrivilegeDBFixture::addAppFail(const std::string &appName,
    const std::string &pkgName, const uid_t uid, const std::string &tizenVer,
    const std::string &authorName, bool isHybrid)
{
    bool appNameExists;
    bool pkgNameExists;
    bool authorNameExists;
    int authorId;

    if (authorName.length() > 0) {
        BOOST_REQUIRE_NO_THROW(testPrivDb->GetAuthorIdByName(authorName, authorId));
        BOOST_REQUIRE_NO_THROW(authorNameExists = testPrivDb->AuthorIdExists(authorId));
    }

    BOOST_REQUIRE_NO_THROW(appNameExists = testPrivDb->AppNameExists(appName));
    BOOST_REQUIRE_NO_THROW(pkgNameExists = testPrivDb->PkgNameExists(pkgName));

    BOOST_REQUIRE_THROW(testPrivDb->AddApplication(appName, pkgName, uid, tizenVer,
        authorName, isHybrid), PrivilegeDb::Exception::ConstraintError);

    BOOST_REQUIRE_MESSAGE(appNameExists == testPrivDb->AppNameExists(appName),
        "AppNameExists wrongly changed value after unsuccessful  installation.");
    BOOST_REQUIRE_MESSAGE(pkgNameExists == testPrivDb->PkgNameExists(pkgName),
        "PkgNameExists wrongly changed value after unsuccessful  installation.");

    if (authorName.length() > 0) {
        BOOST_REQUIRE_NO_THROW(testPrivDb->GetAuthorIdByName(authorName, authorId));
        BOOST_REQUIRE_MESSAGE(authorNameExists == testPrivDb->AuthorIdExists(authorId),
        "AuthorIdExists wrongly changed value after unsuccessful  installation.");
    }
}

void PrivilegeDBFixture::removeApp(const std::string &appName,
    const uid_t uid, bool expAppNameIsNoMore, bool expPkgNameIsNoMore, bool expAuthorNameIsNoMore)
{
    bool appNameIsNoMore = false;
    bool pkgNameIsNoMore = false;
    bool authorNameIsNoMore = false;

    BOOST_REQUIRE_NO_THROW(testPrivDb->RemoveApplication(appName, uid,
        appNameIsNoMore, pkgNameIsNoMore, authorNameIsNoMore));

    BOOST_REQUIRE_MESSAGE(expAppNameIsNoMore == appNameIsNoMore,
        "Wrong value of appNameIsNoMore is: " << appNameIsNoMore << " should be: "
        << expAppNameIsNoMore);
    BOOST_REQUIRE_MESSAGE(expPkgNameIsNoMore == pkgNameIsNoMore,
        "Wrong value of appNameIsNoMore is: " << pkgNameIsNoMore << " should be: "
        << expPkgNameIsNoMore);
    BOOST_REQUIRE_MESSAGE(expAuthorNameIsNoMore == authorNameIsNoMore,
        "Wrong value of appNameIsNoMore is: " << authorNameIsNoMore << " should be: "
         << expAuthorNameIsNoMore);
}

void PrivilegeDBFixture::removeAppSuccess(const std::string &appName,
    const uid_t uid)
{
    bool appNameIsNoMore = false;
    bool pkgNameIsNoMore = false;
    bool authorNameIsNoMore = false;
    BOOST_REQUIRE_NO_THROW(testPrivDb->RemoveApplication(appName, uid,
        appNameIsNoMore, pkgNameIsNoMore, authorNameIsNoMore));
}

void PrivilegeDBFixture::checkPrivateSharing(const std::string &ownerAppName,
    const std::string &targetAppName, const std::string &path, int expectedPathCount,
    int expectedOwnerTargetCount, int expectedTargetPathCount)
{
    int pathCount;
    BOOST_REQUIRE_NO_THROW(testPrivDb->GetPathSharingCount(path, pathCount));
    BOOST_CHECK_MESSAGE(pathCount == expectedPathCount,
    "GetPathSharingCount for path: "  << path << " returned: " << pathCount
           << " expected: " << expectedPathCount);

    int ownerTargetCount;
    BOOST_REQUIRE_NO_THROW(testPrivDb->GetOwnerTargetSharingCount(ownerAppName,
        targetAppName, ownerTargetCount));
    BOOST_CHECK_MESSAGE(ownerTargetCount == expectedOwnerTargetCount,
       "GetOwnerTargetSharingCount for path: "  << path << ", owner: " << ownerAppName
        << " target:" << targetAppName << " returned: " << ownerTargetCount
        << " expected: " << expectedOwnerTargetCount);

    int targetPathCount;
    BOOST_REQUIRE_NO_THROW(testPrivDb->GetTargetPathSharingCount(targetAppName,
        path, targetPathCount));
    BOOST_CHECK_MESSAGE(targetPathCount == expectedTargetPathCount,
        "GetTargetPathSharingCount for path: " << path << " target:" << targetAppName
         << " returned: " << targetPathCount << " expected: " << expectedTargetPathCount);
};

const bool PrivilegeDBFixture::Hybrid = true;

const bool PrivilegeDBFixture::NotHybrid = false;

std::string PrivilegeDBFixture::app(int i)
{
    return genName("appN", i);
};

std::string PrivilegeDBFixture::pkg(int i)
{
    return genName("pkgN", i);
};

std::string PrivilegeDBFixture::tizenVer(int i)
{
    return genName("tizenVerN", i);
};

std::string PrivilegeDBFixture::author(int i)
{
    return genName("authorN", i);
};

std::string PrivilegeDBFixture::path(int i)
{
    return genName("pathN", i);
};

std::string PrivilegeDBFixture::lab(int i)
{
    return genName("labelN", i);
};

uid_t PrivilegeDBFixture::uid(uid_t i)
{
    return FirstUidForTests + i;
}
