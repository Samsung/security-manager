/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       test_privilege_db.cpp
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */

#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include "privilege_db.h"

#define TEST_PRIVILEGE_DB_PATH "/tmp/.security-manager.db"
#define CREATE_PRIVILEGE_DB_CMD "sqlite3 " TEST_PRIVILEGE_DB_PATH \
        " < /usr/share/security-manager/db/db.sql"
#define DELETE_PRIVILEGE_DB_CMD "rm -rf " TEST_PRIVILEGE_DB_PATH

using namespace SecurityManager;


/* Fixtures for the suite and test cases */

struct PrivilegeDBFixture
{
    PrivilegeDBFixture()
    {
        int ret = system(DELETE_PRIVILEGE_DB_CMD);
        BOOST_REQUIRE_MESSAGE(ret >=0, "Function system failed at database delete");
        ret = system(CREATE_PRIVILEGE_DB_CMD);
        BOOST_REQUIRE_MESSAGE(ret >=0, "Could not create test database");
        testPrivilegeDb = new PrivilegeDb(TEST_PRIVILEGE_DB_PATH);

    }
    ~PrivilegeDBFixture()
    {
        int ret = system(DELETE_PRIVILEGE_DB_CMD);
        BOOST_WARN_MESSAGE(ret >=0, "Could not delete test database");
        delete testPrivilegeDb;
    }

    PrivilegeDb *testPrivilegeDb;
    static const bool hybrid = true;
    static const bool notHybrid = false;

    void addApplicationRequireSuccess(const std::string &appName, const std::string &pkgName,
        const uid_t uid, const std::string &tizenVer, const std::string &authorName, bool isHybrid);
    void addApplicationRequireFailure(const std::string &appName, const std::string &pkgName,
        const uid_t uid, const std::string &tizenVer, const std::string &authorName, bool isHybrid);
    void removeApplication(const std::string &appName, const uid_t uid, bool expAppNameIsNoMore,
        bool expPkgNameIsNoMore, bool expAuthorNameIsNoMore);
    void removeApplicationRequireSuccess(const std::string &appName, const uid_t uid);
};

void PrivilegeDBFixture::addApplicationRequireSuccess(const std::string &appName,
    const std::string &pkgName, const uid_t uid, const std::string &tizenVer,
    const std::string &authorName, bool isHybrid)
{
    int authorId;
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->AddApplication(appName, pkgName, uid, tizenVer,
        authorName, isHybrid));
    BOOST_REQUIRE_MESSAGE(testPrivilegeDb->AppNameExists(appName),
        "AppNameExists wrongly not reported " << appName << " as existing application name");
    BOOST_REQUIRE_MESSAGE(testPrivilegeDb->PkgNameExists(pkgName),
        "PkgNameExists wrongly not reported " << pkgName << " as existing package name");
    if (authorName.length() > 0) {
        BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAuthorIdByName(authorName, authorId));
        BOOST_REQUIRE_MESSAGE(testPrivilegeDb->AuthorIdExists(authorId),
            "AuthorIdExists wrongly not reported " << uid << " as existing author id");
    }
}

void PrivilegeDBFixture::addApplicationRequireFailure(const std::string &appName,
    const std::string &pkgName, const uid_t uid, const std::string &tizenVer,
    const std::string &authorName, bool isHybrid)
{
    bool appNameExists;
    bool pkgNameExists;
    bool authorNameExists;
    int authorId;
    if (authorName.length() > 0) {
        BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAuthorIdByName(authorName, authorId));
        BOOST_REQUIRE_NO_THROW(authorNameExists = testPrivilegeDb->AuthorIdExists(authorId));
    }
    BOOST_REQUIRE_NO_THROW(appNameExists = testPrivilegeDb->AppNameExists(appName));
    BOOST_REQUIRE_NO_THROW(pkgNameExists = testPrivilegeDb->PkgNameExists(pkgName));
    BOOST_REQUIRE_THROW(testPrivilegeDb->AddApplication(appName, pkgName, uid, tizenVer,
        authorName, isHybrid), PrivilegeDb::Exception::ConstraintError);
    BOOST_REQUIRE_MESSAGE(appNameExists == testPrivilegeDb->AppNameExists(appName),
        "AppNameExists wrongly changed value after unsuccessful  installation.");
    BOOST_REQUIRE_MESSAGE(pkgNameExists == testPrivilegeDb->PkgNameExists(pkgName),
        "PkgNameExists wrongly changed value after unsuccessful  installation.");
    if (authorName.length() > 0) {
        BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAuthorIdByName(authorName, authorId));
        BOOST_REQUIRE_MESSAGE(authorNameExists == testPrivilegeDb->AuthorIdExists(authorId),
        "AuthorIdExists wrongly changed value after unsuccessful  installation.");
    }
}

void PrivilegeDBFixture::removeApplication(const std::string &appName,
    const uid_t uid, bool expAppNameIsNoMore, bool expPkgNameIsNoMore, bool expAuthorNameIsNoMore)
{
    bool appNameIsNoMore;
    bool pkgNameIsNoMore;
    bool authorNameIsNoMore;
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->RemoveApplication(appName, uid,
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

void PrivilegeDBFixture::removeApplicationRequireSuccess(const std::string &appName,
    const uid_t uid)
{
    bool appNameIsNoMore;
    bool pkgNameIsNoMore;
    bool authorNameIsNoMore;
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->RemoveApplication(appName, uid,
        appNameIsNoMore, pkgNameIsNoMore, authorNameIsNoMore));
}

class Empty {}; //to overwrite the suite fixture

BOOST_FIXTURE_TEST_SUITE(PRIVILEGE_DB_TEST, PrivilegeDBFixture)

// Constructor

BOOST_FIXTURE_TEST_CASE(T100_privilegedb_constructor, Empty)
{
    PrivilegeDb *testPrivilegeDb = nullptr;
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb = new PrivilegeDb());
    delete testPrivilegeDb;
    testPrivilegeDb = nullptr;
    BOOST_REQUIRE_THROW(testPrivilegeDb = new PrivilegeDb("/this/not/exists"),
        PrivilegeDb::Exception::IOError);
    delete testPrivilegeDb;
}

// Transactions

BOOST_AUTO_TEST_CASE(T200_transaction_rollback_commit)
{
    const std::string appN1("appN1T200");
    const std::string pkgN1("pkgN1T200");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T200");
    const std::string authorN1("authorN1T200");
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->BeginTransaction());
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->RollbackTransaction());
    BOOST_REQUIRE_MESSAGE(!testPrivilegeDb->AppNameExists(appN1),
        "AppNameExists wrongly reported " << appN1 << " as existing, despite a rollback");
    BOOST_REQUIRE_THROW(testPrivilegeDb->CommitTransaction(),
        PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T210_transaction_double_rollback)
{
    const std::string appN1("appN1T210");
    const std::string pkgN1("pkgN1T210");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T210");
    const std::string authorN1("authorN1T210");
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->BeginTransaction());
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->RollbackTransaction());
    BOOST_REQUIRE_THROW(testPrivilegeDb->RollbackTransaction(),
        PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T220_commit_without_begin)
{
    BOOST_REQUIRE_THROW(testPrivilegeDb->CommitTransaction(),
        PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T230_rollback_without_begin)
{
    BOOST_REQUIRE_THROW(testPrivilegeDb->RollbackTransaction(),
        PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T240_transaction)
{
    const std::string appN1("appN1T240");
    const std::string pkgN1("pkgN1T240");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T240");
    const std::string authorN1("authorN1T240");
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->BeginTransaction());
    addApplicationRequireSuccess(appN1,pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->CommitTransaction());
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->BeginTransaction());
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->RollbackTransaction());
    BOOST_REQUIRE_MESSAGE(testPrivilegeDb->AppNameExists(appN1),
        "AppNameExists wrongly not reported " << appN1 << " as existing application name");
}

BOOST_AUTO_TEST_CASE(T250_transaction_double_begin)
{
    const std::string appN1("appN1T250");
    const std::string pkgN1("pkgN1T250");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T250");
    const std::string authorN1("authorN1T250");
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->BeginTransaction());
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    BOOST_REQUIRE_THROW(testPrivilegeDb->BeginTransaction(),
        PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T260_transaction_double_commit)
{
    const std::string appN1("appN1T260");
    const std::string pkgN1("pkgN1T260");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T260");
    const std::string authorN1("authorN1T260");
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->BeginTransaction());
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->CommitTransaction());
    BOOST_REQUIRE_THROW(testPrivilegeDb->CommitTransaction(),
        PrivilegeDb::Exception::InternalError);
}

// *Exists, GetApp*

BOOST_AUTO_TEST_CASE(T300_app_name_exists_finds_nothing)
{
    const std::string notAnExistingAppName("notAnExistingAppNameT300");
    BOOST_REQUIRE_MESSAGE(!testPrivilegeDb->AppNameExists(notAnExistingAppName),
        "AppNameExists wrongly reported " << notAnExistingAppName <<
        " as existing application name");
}

BOOST_AUTO_TEST_CASE(T310_pkg_name_exists_finds_nothing)
{
    const std::string notAnExistingPkgName("notAnExistingPkgNameT310");
    BOOST_REQUIRE_MESSAGE(!testPrivilegeDb->PkgNameExists(notAnExistingPkgName),
        "PkgNameExists wrongly reported " << notAnExistingPkgName <<
        " as existing package name");
}

BOOST_AUTO_TEST_CASE(T320_author_id_exists_finds_nothing)
{
    //database is clean, author ids are assigned sequentially from bottom
    const int notExistingAuthorId= 200;
    BOOST_REQUIRE_MESSAGE(!testPrivilegeDb->AuthorIdExists(notExistingAuthorId),
        "AuthorIdExists wrongly reported " << notExistingAuthorId <<
        " as existing author id");
}

BOOST_AUTO_TEST_CASE(T330_app_name_pkg_author_exists)
{
    int authorId;
    const std::string appN1("appN1T330");
    const std::string appN2("appN2T330");
    const std::string appN3("appN3T330");
    const std::string appN4("appN4T330");
    const std::string pkgN1("pkgN1T330");
    const std::string pkgN2("pkgN2T330");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const std::string tizenVer1("tizenVer1T330");
    const std::string authorN1("authorN1T330");
    const std::string authorN2("authorN2T330");

    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN2, uid1, tizenVer1, authorN2, notHybrid);
    addApplicationRequireSuccess(appN3, pkgN2, uid1, tizenVer1, authorN2, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN2, uid1, tizenVer1, authorN2, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN2, uid2, tizenVer1, authorN2, notHybrid);
    BOOST_REQUIRE_MESSAGE(testPrivilegeDb->AppNameExists(appN1),
        "AppNameExists wrongly not reported " << appN1 << " as existing application name");
    BOOST_REQUIRE_MESSAGE(testPrivilegeDb->PkgNameExists(pkgN1),
        "PkgNameExists wrongly not reported " << pkgN1 << " as existing package name");
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAuthorIdByName(authorN1, authorId));
    BOOST_REQUIRE_MESSAGE(testPrivilegeDb->AuthorIdExists(authorId),
        "AuthorIdExists wrongly not found " << authorN1 << " as existing author");
}

BOOST_AUTO_TEST_CASE(T340_get_app_pkg_name)
{
    std::string package1, package2, package3, package4;
    const std::string appN1("appN1T340");
    const std::string appN2("appN2T340");
    const std::string appN3("appN3T340");
    const std::string appN4("appN4T340");
    const std::string pkgN1("pkgN1T340");
    const std::string pkgN2("pkgN2T340");
    const std::string pkgN3("pkgN3T340");
    const std::string pkgN4("pkgN4T340");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const uid_t uid3(99903);
    const uid_t uid4(99904);
    const std::string tizenVer1("tizenVer1T340");
    const std::string tizenVer2("tizenVer2T340");
    const std::string tizenVer3("tizenVer3T340");
    const std::string authorN1("authorN1T340");
    const std::string authorN2("authorN2T340");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN2, uid2, tizenVer2, authorN2, hybrid);
    addApplicationRequireSuccess(appN3, pkgN3, uid3, tizenVer3, authorN2, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN3, uid4, tizenVer3, authorN2, notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppPkgName(appN1, package1));
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppPkgName(appN2, package2));
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppPkgName(appN3, package3));
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppPkgName(appN4, package4));
    BOOST_REQUIRE_MESSAGE(package1 == pkgN1, "Expected package name for app: " <<  appN1
        << " to be: " << pkgN1 << " got: " << package1);
    BOOST_REQUIRE_MESSAGE(package2 == pkgN2, "Expected package name for app: " <<  appN2
        << " to be: " << pkgN2 << " got: " << package2);
    BOOST_REQUIRE_MESSAGE(package3 == pkgN3, "Expected package name for app: " <<  appN3
        << " to be: " << pkgN3 << " got: " << package3);
    BOOST_REQUIRE_MESSAGE(package4 == pkgN3, "Expected package name for app: " <<  appN4
        << " to be: " << pkgN3 << " got: " << package4);
}

BOOST_AUTO_TEST_CASE(T350_get_app_version)
{
    std::string version1, version2, version3, version4;
    const std::string appN1("appN1T350");
    const std::string appN2("appN2T350");
    const std::string appN3("appN3T350");
    const std::string appN4("appN4T350");
    const std::string pkgN1("pkgN1T350");
    const std::string pkgN2("pkgN2T350");
    const std::string pkgN3("pkgN3T350");
    const std::string pkgN4("pkgN4T350");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const uid_t uid3(99903);
    const uid_t uid4(99904);
    const std::string tizenVer1("tizenVer1T350");
    const std::string tizenVer2("tizenVer2T350");
    const std::string tizenVer3("tizenVer3T350");
    const std::string authorN1("authorN1T350");
    const std::string authorN2("authorN2T350");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN2, uid2, tizenVer2, authorN2, hybrid);
    addApplicationRequireSuccess(appN3, pkgN3, uid3, tizenVer3, authorN2, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN3, uid4, tizenVer3, authorN2, notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppVersion(appN1, version1));
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppVersion(appN2, version2));
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppVersion(appN3, version3));
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppVersion(appN4, version4));
    BOOST_REQUIRE_MESSAGE(version1 == tizenVer1, "Expected Tizen version for app: "
        << appN1 << " to be: " << tizenVer1 << " got: " << version1);
    BOOST_REQUIRE_MESSAGE(version2 == tizenVer2, "Expected Tizen version for app: "
        << appN2 << " to be: " << tizenVer2 << " got: " << version2);
    BOOST_REQUIRE_MESSAGE(version3 == tizenVer3, "Expected Tizen version for app: "
        << appN3 << " to be: " << tizenVer3 << " got: " << version3);
    BOOST_REQUIRE_MESSAGE(version4 == tizenVer3, "Expected Tizen version for app: "
        << appN4 << " to be: " << tizenVer3 << " got: " << version4);
}

BOOST_AUTO_TEST_CASE(T360_get_app_package_finds_nothing)
{
    std::string package;
    const std::string appN1("appN1T360");
    const std::string appN2("appN2T360");
    const std::string pkgN1("pkgN1T360");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T360");
    const std::string authorN1("authorN1T360");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppPkgName(appN2, package));
    BOOST_REQUIRE_MESSAGE(package.empty(), "Expected empty string as package of nonexisting app "
        << "got: " << package);
}

BOOST_AUTO_TEST_CASE(T370_get_app_version_finds_nothing)
{
    std::string version;
    const std::string appN1("appN1T370");
    const std::string appN2("appN2T370");
    const std::string pkgN1("pkgN1T370");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T370");
    const std::string authorN1("authorN1T370");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAppVersion(appN2, version));
    BOOST_REQUIRE_MESSAGE(version.empty(),
        "Expected empty string as version of nonexisting app got: " << version);
}

// AddApplication

BOOST_AUTO_TEST_CASE(T400_add_application_simple)
{
    const std::string appN1("appN1T400");
    const std::string pkgN1("pkgN1T400");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T400");
    const std::string authorN1("authorN1T400");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T410_add_application_empty_name)
{
    const std::string pkgN1("pkgN1T410");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T410");
    const std::string authorN1("authorN1T410");
    addApplicationRequireSuccess("", pkgN1, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T420_add_application_long_name)
{
    const std::string appN1("IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongString"
        "IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongStringappN1T420");
    const std::string pkgN1("pkgN1T420");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T420");
    const std::string authorN1("authorN1T420");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T430_add_application_name_with_spaces)
{
    const std::string appN1("appN1 with spaces T430");
    const std::string pkgN1("pkgN1T430");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T430");
    const std::string authorN1("authorN1T430");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T440_add_application_empty_pkg_name)
{
    const std::string appN1("appN1T440");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T440");
    const std::string authorN1("authorN1T440");
    addApplicationRequireSuccess(appN1, "", uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T450_add_application_long_pkg_name)
{
    const std::string appN1("appN1T450");
    const std::string pkgN1("IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongString"
        "IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongStringpkgN1T450");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T450");
    const std::string authorN1("authorN1T450");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T460_add_application_name_with_spaces_pkg)
{
    const std::string appN1("appN1T460");
    const std::string pkgN1("pkgN1 with spaces T460");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T460");
    const std::string authorN1("authorN1T460");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T470_add_application_empty_tizenVer)
{
    const std::string appN1("appN1T470");
    const std::string pkgN1("pkgN1T470");
    const uid_t uid1(99901);
    const std::string authorN1("authorN1T470");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, "", authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T480_add_application_long_tizenVer)
{
    const std::string appN1("appN1T480");
    const std::string pkgN1("pkgN1T480");
    const uid_t uid1(99901);
    const std::string tizenVer1("IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongString"
        "IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongStringtizenN1T480");
    const std::string authorN1("authorN1T480");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T490_add_application_tizenVer_with_spaces)
{
    const std::string appN1("appN1T490");
    const std::string pkgN1("pkgN1T490");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer with spaces T490");
    const std::string authorN1("authorN1T490");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
}
BOOST_AUTO_TEST_CASE(T500_add_application_twice_to_same_package)
{
    const std::string appN1("appN1T500");
    const std::string pkgN1("pkgN1T500");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T500");
    const std::string authorN1("authorN1T500");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T510_add_application_to_different_packages)
{
    const std::string appN1("appN1T510");
    const std::string pkgN1("pkgN1T510");
    const std::string pkgN2("pkgN2T510");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T510");
    const std::string authorN1("authorN1T510");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    addApplicationRequireFailure(appN1, pkgN2, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T520_add_application_two_tizen_versions_to_same_package)
{
    const std::string appN1("appN1T520");
    const std::string pkgN1("pkgN1T520");
    const std::string pkgN2("pkgN2T520");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T520");
    const std::string tizenVer2("tizenVer2T520");
    const std::string authorN1("authorN1T520");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    addApplicationRequireFailure(appN1, pkgN1, uid1, tizenVer2, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T530_add_application_two_tizen_versions_to_two_packages)
{
    const std::string appN1("appN1T530");
    const std::string pkgN1("pkgN1T530");
    const std::string pkgN2("pkgN2T530");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T170");
    const std::string tizenVer2("tizenVer2T170");
    const std::string authorN1("authorN1T170");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireFailure(appN1, pkgN2, uid1, tizenVer2, authorN1, notHybrid);
}

BOOST_AUTO_TEST_CASE(T540_add_application_different_hybrid_to_package)
{
    const std::string appN1("appN1T540");
    const std::string pkgN1("pkgN1T540");
    const std::string pkgN2("pkgN2T540");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const std::string tizenVer1("tizenVer1T540");
    const std::string authorN1("authorN1T540");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireFailure(appN1, pkgN1, uid2, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T550_add_application_same_name)
{
    const std::string appN1("appN1T550");
    const std::string pkgN1("pkgN1T550");
    const std::string pkgN2("pkgN2T550");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const std::string tizenVer1("tizenVer1T550");
    const std::string tizenVer2("tizenVer2T550");
    const std::string authorN1("authorN1T550");
    const std::string authorN2("authorN2T550");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    addApplicationRequireFailure(appN1, pkgN2, uid2, tizenVer2, authorN2, notHybrid);
}

BOOST_AUTO_TEST_CASE(T560_add_five_applications_to_same_package)
{
    const std::string appN1("appN1T560");
    const std::string appN2("appN2T560");
    const std::string appN3("appN3T560");
    const std::string appN4("appN4T560");
    const std::string appN5("appN5T560");
    const std::string pkgN1("pkgN1T560");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T560");
    const std::string authorN1("authorN1T560");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    addApplicationRequireSuccess(appN2, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    addApplicationRequireSuccess(appN3, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    addApplicationRequireSuccess(appN4, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    addApplicationRequireSuccess(appN5, pkgN1, uid1, tizenVer1, authorN1, hybrid);
}

BOOST_AUTO_TEST_CASE(T570_add_applications_with_different_author_to_package)
{
    const std::string appN1("appN1T570");
    const std::string appN2("appN2T570");
    const std::string pkgN1("pkgN1T570");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T570");
    const std::string authorN1("authorN1T570");
    const std::string authorN2("authorN2T570");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireFailure(appN2, pkgN1, uid1, tizenVer1, authorN2, notHybrid);
    BOOST_REQUIRE_MESSAGE(!testPrivilegeDb->AppNameExists(appN2),
        "AppNameExists wrongly reported " << appN2 << " as existing application name");
}

BOOST_AUTO_TEST_CASE(T580_add_applications_with_different_authors_to_packages)
{
    const std::string appN1("appN1T580");
    const std::string appN2("appN2T580");
    const std::string appN3("appN3T580");
    const std::string appN4("appN4T580");
    const std::string pkgN1("pkgN1T580");
    const std::string pkgN2("pkgN2T580");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T580");
    const std::string authorN1("authorN1T580");
    const std::string authorN2("authorN2T580");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN3, pkgN2, uid1, tizenVer1, authorN2, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN2, uid1, tizenVer1, authorN2, notHybrid);
}

BOOST_AUTO_TEST_CASE(T590_add_applications_with_empty_noempty_author)
{
    const std::string appN1("appN1T590");
    const std::string appN2("appN2T590");
    const std::string appN3("appN3T590");
    const std::string pkgN1("pkgN1T590");
    const std::string pkgN2("pkgN2T590");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T590");
    const std::string authorN1("authorN1T590");
    int authorIdPkg;
    int authorId;
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, "", notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetPkgAuthorId(pkgN1, authorIdPkg));
    BOOST_REQUIRE_MESSAGE(authorIdPkg == -1, "Wrong author id returned: " << authorIdPkg
        << " expected: -1");
    addApplicationRequireSuccess(appN2, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetPkgAuthorId(pkgN1, authorIdPkg));
    BOOST_REQUIRE_MESSAGE(authorIdPkg != -1, "Wrong author id returned: -1");
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAuthorIdByName(authorN1, authorId));
    BOOST_REQUIRE_MESSAGE(authorId == authorIdPkg, "Author id returned by GetAuthorIdByName: "
        << authorId << " does not match author id returned by GetPkgAuthorId: " << authorIdPkg);
    addApplicationRequireSuccess(appN3, pkgN1, uid1, tizenVer1, "", notHybrid);
    BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetPkgAuthorId(pkgN2, authorIdPkg));
    BOOST_REQUIRE_MESSAGE(authorIdPkg == -1, "Wrong author id returned: " << authorIdPkg
        << " expected: -1");
}

BOOST_AUTO_TEST_CASE(T600_add_applications_with_different_isHybrid_false_true)
{
    const std::string appN1("appN1T600");
    const std::string appN2("appN2T600");
    const std::string pkgN1("pkgN1T600");
    const std::string pkgN2("pkgN2T600");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T600");
    const std::string authorN1("authorN1T600");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireFailure(appN2, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    BOOST_REQUIRE_MESSAGE(!testPrivilegeDb->AppNameExists(appN2),
        "AppNameExists wrongly reported " << appN2 << " as existing application name");
}

BOOST_AUTO_TEST_CASE(T610_add_applications_with_different_isHybrid_true_false)
{
    const std::string appN1("appN1T610");
    const std::string appN2("appN2T610");
    const std::string pkgN1("pkgN1T610");
    const std::string pkgN2("pkgN2T610");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T610");
    const std::string authorN1("authorN1T610");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    addApplicationRequireFailure(appN2, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    BOOST_REQUIRE_MESSAGE(!testPrivilegeDb->AppNameExists(appN2),
        "AppNameExists wrongly reported " << appN2 << " as existing application name");
}

BOOST_AUTO_TEST_CASE(T620_add_applications_with_different_isHybrid_to_two_packages)
{
    const std::string appN1("appN1T620");
    const std::string appN2("appN2T620");
    const std::string appN3("appN3T620");
    const std::string appN4("appN4T620");
    const std::string pkgN1("pkgN1T620");
    const std::string pkgN2("pkgN2T620");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T620");
    const std::string authorN1("authorN1T620");
    const std::string authorN2("authorN2T620");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN3, pkgN2, uid1, tizenVer1, authorN2, hybrid);
    addApplicationRequireSuccess(appN4, pkgN2, uid1, tizenVer1, authorN2, hybrid);
}

BOOST_AUTO_TEST_CASE(T630_add_applications_with_different_uid_to_package)
{
    const std::string appN1("appN1T630");
    const std::string pkgN1("pkgN1T630");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const std::string tizenVer1("tizenVer1T630");
    const std::string authorN1("authorN1T630");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN1, pkgN1, uid2, tizenVer1, authorN1, notHybrid);
}

BOOST_AUTO_TEST_CASE(T640_add_applications_with_different_uid_to_two_packages)
{
    const std::string appN1("appN1T640");
    const std::string pkgN1("pkgN1T640");
    const std::string pkgN2("pkgN2T640");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const std::string tizenVer1("tizenVer1T640");
    const std::string authorN1("authorN1T640");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireFailure(appN1, pkgN2, uid2, tizenVer1, authorN1, notHybrid);
}

// RemoveApplication

BOOST_AUTO_TEST_CASE(T700_add_remove_add_application)
{
    const std::string appN1("appN1T700");
    const std::string pkgN1("pkgN1T700");
    const std::string pkgN2("pkgN2T700");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T700");
    const std::string authorN1("authorN1T700");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    removeApplication(appN1,uid1, true, true, true);
    addApplicationRequireSuccess(appN1, pkgN2, uid1, tizenVer1, authorN1, notHybrid);
}

BOOST_AUTO_TEST_CASE(T710_add_double_remove_add_application)
{
    const std::string appN1("appN1T710");
    const std::string pkgN1("pkgN1T710");
    const std::string pkgN2("pkgN2T710");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T710");
    const std::string authorN1("authorN1T710");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    removeApplication(appN1,uid1, true, true, true);
    removeApplication(appN1,uid1, true, true, true);
    addApplicationRequireSuccess(appN1, pkgN2, uid1, tizenVer1, authorN1, notHybrid);
}

BOOST_AUTO_TEST_CASE(T720_add_remove_application_to_different_users)
{
    const std::string appN1("appN1T720");
    const std::string pkgN1("pkgN1T720");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const std::string tizenVer1("tizenVer1T720");
    const std::string authorN1("authorN1T720");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN1, pkgN1, uid2, tizenVer1, authorN1, notHybrid);
    removeApplication(appN1, uid1, false, false, false);
    removeApplication(appN1, uid2, true, true, true);
}

BOOST_AUTO_TEST_CASE(T730_app_name_pkg_author_exists_with_remove)
{
    const std::string appN1("appN1T730");
    const std::string appN2("appN2T730");
    const std::string appN3("appN3T730");
    const std::string appN4("appN4T730");
    const std::string appN5("appN5T730");
    const std::string pkgN1("pkgN1T730");
    const std::string pkgN2("pkgN2T730");
    const std::string pkgN3("pkgN3T730");
    const std::string pkgN4("pkgN4T730");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const uid_t uid3(99903);
    const uid_t uid4(99904);
    const std::string tizenVer1("tizenVer1T730");
    const std::string tizenVer2("tizenVer2T730");
    const std::string tizenVer3("tizenVer3T730");
    const std::string tizenVer4("tizenVer4T730");
    const std::string authorN1("authorN1T730");
    const std::string authorN2("authorN2T730");
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN2, uid2, tizenVer2, authorN2, hybrid);
    addApplicationRequireSuccess(appN3, pkgN3, uid3, tizenVer3, authorN2, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN3, uid4, tizenVer3, authorN2, notHybrid);
    removeApplication(appN1, uid1, true, true, true);
    removeApplication(appN3, uid3, true, false, false);
    removeApplication(appN4, uid4, true, true, false);
    removeApplication(appN4, uid4, true, true, false);
    removeApplication(appN2, uid2, true, true, true);
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN2, uid2, tizenVer2, authorN2, hybrid);
    addApplicationRequireSuccess(appN3, pkgN3, uid3, tizenVer3, authorN2, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN3, uid4, tizenVer3, authorN2, notHybrid);
    addApplicationRequireSuccess(appN5, pkgN4, uid4, tizenVer1, authorN2, notHybrid);
    removeApplication(appN1, uid2, false, false, false);
    removeApplication(appN1, uid1, true, true, true);
    removeApplication(appN2, uid2, true, true, false);
    removeApplication(appN3, uid3, true, false, false);
    removeApplication(appN4, uid4, true, true, false);
    removeApplication(appN5, uid4, true, true, true);
}

BOOST_AUTO_TEST_CASE(T740_remove_application_with_no_effect)
{
    const std::string appN1("appN1T740");
    const std::string appN2("appN2T740");
    const std::string pkgN1("pkgN1T740");
    const std::string pkgN2("pkgN2T740");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const std::string tizenVer1("tizenVer1T740");
    const std::string authorN1("authorN1T740");
    removeApplicationRequireSuccess(appN1, uid1);
    addApplicationRequireSuccess(appN2, pkgN2, uid2, tizenVer1, authorN1, notHybrid);
    removeApplication(appN2, uid1, false, false, false);  //uid1 != uid2
    BOOST_REQUIRE_MESSAGE(testPrivilegeDb->AppNameExists(appN2),
        "AppNameExists wrongly not reported " << appN2 << " as existing application name");
}

// Get*

BOOST_AUTO_TEST_CASE(T800_get_user_apps)
{
    const std::string appN1("appN1T800");
    const std::string appN2("appN2T800");
    const std::string appN3("appN3T800");
    const std::string appN4("appN4T800");
    const std::string appN5("appN5T800");
    const std::string pkgN1("pkgN1T800");
    const std::string pkgN2("pkgN2T800");
    const std::string pkgN3("pkgN3T800");
    const std::string pkgN4("pkgN4T800");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const uid_t uid3(99903);
    const uid_t uid4(99904);
    const std::string tizenVer1("tizenVer1T800");
    const std::string tizenVer2("tizenVer2T800");
    const std::string tizenVer3("tizenVer3T800");
    const std::string authorN1("authorN1T800");
    const std::string authorN2("authorN2T800");
    addApplicationRequireSuccess(appN1, pkgN1, uid2, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN2, uid3, tizenVer2, authorN2, hybrid);
    addApplicationRequireSuccess(appN3, pkgN3, uid3, tizenVer3, authorN2, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN3, uid3, tizenVer3, authorN2, notHybrid);
    addApplicationRequireSuccess(appN5, pkgN4, uid4, tizenVer1, authorN2, notHybrid);

    auto checkGetUserApps = [&](const uid_t uid, std::vector<std::string> expectedApps)
    {
        std::vector<std::string> apps;
        BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetUserApps(uid, apps));
        std::sort(apps.begin(), apps.end());
        std::sort(expectedApps.begin(), expectedApps.end());
        BOOST_CHECK_EQUAL_COLLECTIONS(apps.begin(), apps.end(),
            expectedApps.begin(), expectedApps.end());
    };

    checkGetUserApps(uid1, {});
    checkGetUserApps(uid2, {appN1});
    checkGetUserApps(uid3, {appN2, appN3, appN4});
    checkGetUserApps(uid4, {appN5});

    removeApplicationRequireSuccess(appN2, uid3);
    removeApplicationRequireSuccess(appN3, uid3);
    addApplicationRequireSuccess(appN2, pkgN4, uid4, tizenVer1, authorN2, notHybrid);
    addApplicationRequireSuccess(appN3, pkgN4, uid4, tizenVer1, authorN2, notHybrid);

    checkGetUserApps(uid3, {appN4});
    checkGetUserApps(uid4, {appN2, appN3, appN5});
}

BOOST_AUTO_TEST_CASE(T810_get_user_packages)
{
    const std::string appN1("appN1T810");
    const std::string appN2("appN2T810");
    const std::string appN3("appN3T810");
    const std::string appN4("appN4T810");
    const std::string appN5("appN5T810");
    const std::string pkgN1("pkgN1T810");
    const std::string pkgN2("pkgN2T810");
    const std::string pkgN3("pkgN3T810");
    const std::string pkgN4("pkgN4T810");
    const std::string pkgN5("pkgN5T810");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const uid_t uid3(99903);
    const uid_t uid4(99904);
    const std::string tizenVer1("tizenVer1T810");
    const std::string authorN1("authorN1T810");
    const std::string authorN2("authorN2T810");
    addApplicationRequireSuccess(appN1, pkgN1, uid2, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN2, uid3, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN3, pkgN3, uid3, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN4, uid3, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN5, pkgN5, uid4, tizenVer1, authorN1, notHybrid);

    auto checkGetUserPkgs = [&](const uid_t uid, std::vector<std::string> expectedPkgs)
    {
        std::vector<std::string> pkgs;
        BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetUserPkgs(uid, pkgs));
        std::sort(pkgs.begin(), pkgs.end());
        std::sort(expectedPkgs.begin(), expectedPkgs.end());
        BOOST_CHECK_EQUAL_COLLECTIONS(pkgs.begin(), pkgs.end(),
            expectedPkgs.begin(), expectedPkgs.end());
    };

    checkGetUserPkgs(uid1, {});
    checkGetUserPkgs(uid2, {pkgN1});
    checkGetUserPkgs(uid3, {pkgN2, pkgN3, pkgN4});
    checkGetUserPkgs(uid4, {pkgN5});

    removeApplicationRequireSuccess(appN2, uid3);
    removeApplicationRequireSuccess(appN3, uid3);
    addApplicationRequireSuccess(appN2, pkgN2, uid4, tizenVer1, authorN2, notHybrid);
    addApplicationRequireSuccess(appN3, pkgN3, uid4, tizenVer1, authorN2, notHybrid);

    checkGetUserPkgs(uid3, {pkgN4});
    checkGetUserPkgs(uid4, {pkgN2, pkgN3, pkgN5});
}

BOOST_AUTO_TEST_CASE(T820_get_pkg_apps)
{
    const std::string appN1("appN1T820");
    const std::string appN2("appN2T820");
    const std::string appN3("appN3T820");
    const std::string appN4("appN4T820");
    const std::string appN5("appN5T820");
    const std::string pkgN1("pkgN1T820");
    const std::string pkgN2("pkgN2T820");
    const std::string pkgN3("pkgN3T820");
    const std::string pkgN4("pkgN4T820");
    const uid_t uid1(99902);
    const std::string tizenVer1("tizenVer1T820");
    const std::string authorN1("authorN1T820");
    const std::string authorN2("authorN2T820");
    addApplicationRequireSuccess(appN1, pkgN2, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN3, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN3, pkgN3, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN4, pkgN3, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN5, pkgN4, uid1, tizenVer1, authorN1, notHybrid);

    auto checkGetPkgApps = [&](const std::string &package, std::vector<std::string> expectedApps)
    {
        std::vector<std::string> apps;
        BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetPkgApps(package, apps));
        std::sort(apps.begin(), apps.end());
        std::sort(expectedApps.begin(), expectedApps.end());
        BOOST_CHECK_EQUAL_COLLECTIONS(apps.begin(), apps.end(),
            expectedApps.begin(), expectedApps.end());
    };

    checkGetPkgApps(pkgN1, {});
    checkGetPkgApps(pkgN2, {appN1});
    checkGetPkgApps(pkgN3, {appN2, appN3, appN4});
    checkGetPkgApps(pkgN4, {appN5});

    removeApplicationRequireSuccess(appN1, uid1);
    removeApplicationRequireSuccess(appN2, uid1);
    removeApplicationRequireSuccess(appN3, uid1);
    addApplicationRequireSuccess(appN1, pkgN4, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN4, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN3, pkgN1, uid1, tizenVer1, authorN1, notHybrid);

    checkGetPkgApps(pkgN1, {appN3});
    checkGetPkgApps(pkgN2, {});
    checkGetPkgApps(pkgN3, {appN4});
    checkGetPkgApps(pkgN4, {appN1, appN2, appN5});
}

BOOST_AUTO_TEST_CASE(T830_get_all_packages)
{
    const std::string appN1("appN1T830");
    const std::string appN2("appN2T830");
    const std::string appN3("appN3T830");
    const std::string appN4("appN4T830");
    const std::string appN5("appN5T830");
    const std::string pkgN1("pkgN1T830");
    const std::string pkgN2("pkgN2T830");
    const std::string pkgN3("pkgN3T830");
    const std::string pkgN4("pkgN4T830");
    const uid_t uid1(99901);
    const std::string tizenVer1("tizenVer1T830");
    const std::string authorN1("authorN1T830");
    auto checkGetAllPackages = [&](std::vector<std::string> expectedPackages)
    {
        std::vector<std::string> packages;
        BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAllPackages(packages));
        std::sort(packages.begin(), packages.end());
        std::sort(expectedPackages.begin(), expectedPackages.end());
        BOOST_CHECK_EQUAL_COLLECTIONS(packages.begin(), packages.end(),
        expectedPackages.begin(), expectedPackages.end());
    };

    checkGetAllPackages({});
    addApplicationRequireSuccess(appN1, pkgN2, uid1, tizenVer1, authorN1, notHybrid);
    checkGetAllPackages({pkgN2});
    addApplicationRequireSuccess(appN2, pkgN3, uid1, tizenVer1, authorN1, notHybrid);
    checkGetAllPackages({pkgN2, pkgN3});
    addApplicationRequireSuccess(appN3, pkgN3, uid1, tizenVer1, authorN1, notHybrid);
    checkGetAllPackages({pkgN2, pkgN3});
    addApplicationRequireSuccess(appN4, pkgN3, uid1, tizenVer1, authorN1, notHybrid);
    checkGetAllPackages({pkgN2, pkgN3});
    addApplicationRequireSuccess(appN5, pkgN4, uid1, tizenVer1, authorN1, notHybrid);
    checkGetAllPackages({pkgN2, pkgN3, pkgN4});
    removeApplicationRequireSuccess(appN1, uid1);
    checkGetAllPackages({pkgN3, pkgN4});
    removeApplicationRequireSuccess(appN2, uid1);
    checkGetAllPackages({pkgN3, pkgN4});
    removeApplicationRequireSuccess(appN3, uid1);
    removeApplicationRequireSuccess(appN4, uid1);
    checkGetAllPackages({pkgN4});
    addApplicationRequireSuccess(appN1, pkgN4, uid1, tizenVer1, authorN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN4, uid1, tizenVer1, authorN1, notHybrid);
    checkGetAllPackages({pkgN4});
    addApplicationRequireSuccess(appN3, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    checkGetAllPackages({pkgN1, pkgN4});
}

BOOST_AUTO_TEST_CASE(T840_get_pkg_author_id)
{
    const std::string appN1("appN1T840");
    const std::string appN2("appN2T840");
    const std::string appN3("appN3T840");
    const std::string pkgN1("pkgN1T840");
    const std::string pkgN2("pkgN2T840");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const uid_t uid3(99903);
    const std::string tizenVer1("tizenVer1T840");
    const std::string authorN1("authorN1T840");
    const std::string authorN2("authorN2T840");
    const std::string authorN3("authorN3T840");
    auto checkGetPkgAuthorId = [&](const std::string &pkgName, int expectedAuthorId)
    {
        int authorId;
        BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetPkgAuthorId(pkgName, authorId));
        BOOST_CHECK_MESSAGE(expectedAuthorId == authorId, "GetPkgAuthorId for package: "
            << pkgName << " returned authorId: " << authorId << " expected: " << expectedAuthorId);
    };

    checkGetPkgAuthorId(pkgN1, -1);
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    checkGetPkgAuthorId(pkgN1, 1);
    addApplicationRequireSuccess(appN2, pkgN2, uid2, tizenVer1, authorN2, hybrid);
    checkGetPkgAuthorId(pkgN2, 2);
    addApplicationRequireSuccess(appN3, pkgN2, uid2, tizenVer1, authorN2, hybrid);
    checkGetPkgAuthorId(pkgN2, 2);
    removeApplicationRequireSuccess(appN1, uid1);
    checkGetPkgAuthorId(pkgN1, -1);
    addApplicationRequireSuccess(appN1, pkgN1, uid3, tizenVer1, authorN3, hybrid);
    checkGetPkgAuthorId(pkgN1, 3);
}

BOOST_AUTO_TEST_CASE(T850_get_pkg_author_id_by_name)
{
    const std::string appN1("appN1T850");
    const std::string appN2("appN2T850");
    const std::string pkgN1("pkgN1T850");
    const std::string pkgN2("pkgN2T850");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const std::string tizenVer1("tizenVer1T850");
    const std::string authorN1("authorN1T850");
    const std::string authorN2("authorN2T850");
    auto checkGetAuthorIdByName = [&](const std::string &authorName, int expectedAuthorId)
    {
        int authorId;
        BOOST_REQUIRE_NO_THROW(testPrivilegeDb->GetAuthorIdByName(authorName, authorId));
        BOOST_CHECK_MESSAGE(expectedAuthorId == authorId, "GetAuthorIdByName for authorName: "
            << authorName << " returned wrong authorId: " << authorId << " expected: "
            << expectedAuthorId);
    };

    checkGetAuthorIdByName(authorN1, -1);
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    checkGetAuthorIdByName(authorN1, 1);
    addApplicationRequireSuccess(appN2, pkgN2, uid2, tizenVer1, authorN2, notHybrid);
    checkGetAuthorIdByName(authorN2, 2);
    removeApplicationRequireSuccess(appN1, uid1);
    checkGetAuthorIdByName(authorN1, -1);
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, hybrid);
    checkGetAuthorIdByName(authorN1, 3);
}

BOOST_AUTO_TEST_CASE(T860_is_package_hybrid)
{
    const std::string appN1("appN1T860");
    const std::string appN2("appN2T860");
    const std::string appN3("appN3T860");
    const std::string pkgN1("pkgN1T860");
    const std::string pkgN2("pkgN2T860");
    const std::string pkgN3("pkgN3T860");
    const uid_t uid1(99901);
    const uid_t uid2(99902);
    const std::string tizenVer1("tizenVer1T860");
    const std::string authorN1("authorN1T860");
    const std::string authorN2("authorN2T860");
    auto checkIsPackageHybrid = [&](const std::string &pkgName, bool expectedIsHybrid)
    {
        bool isHybrid;
        BOOST_REQUIRE_NO_THROW(isHybrid = testPrivilegeDb->IsPackageHybrid(pkgName));
        BOOST_CHECK_MESSAGE(expectedIsHybrid == isHybrid, "IsPackageHybrid for pkgName: "
            << pkgName << " returned wrong value: " << isHybrid << " expected: "
            << expectedIsHybrid);
    };

    checkIsPackageHybrid(pkgN1, notHybrid);
    addApplicationRequireSuccess(appN1, pkgN1, uid1, tizenVer1, authorN1, notHybrid);
    checkIsPackageHybrid(pkgN1, notHybrid);
    addApplicationRequireSuccess(appN2, pkgN2, uid2, tizenVer1, authorN2, notHybrid);
    checkIsPackageHybrid(pkgN2, notHybrid);
    addApplicationRequireSuccess(appN3, pkgN3, uid1, tizenVer1, authorN1, hybrid);
    checkIsPackageHybrid(pkgN3, hybrid);
}

BOOST_AUTO_TEST_SUITE_END()

