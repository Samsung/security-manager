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
 * @file       test_privilege_db_app_pkg_getters.cpp
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */

#include <string>
#include <sys/types.h>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include "privilege_db.h"
#include "privilege_db_fixture.h"

//Fixture for getters

struct PrivilegeDBGettersFixture : PrivilegeDBFixture
{
    void checkGetAllPackages(std::vector<std::string> expectedPackages);
    void checkGetAuthorIdByName(const std::string &authorName, int expectedAuthorId);
    void checkGetPkgApps(const std::string &package, std::vector<std::string> expectedApps);
    void checkGetPkgAuthorId(const std::string &pkgName, int expectedAuthorId);
    void checkGetUserApps(const uid_t uid, std::vector<std::string> expectedApps);
    void checkGetUserPkgs(const uid_t uid, std::vector<std::string> expectedPkgs);
    void checkIsPackageHybrid(const std::string &pkgName, bool expectedIsHybrid);
};

void PrivilegeDBGettersFixture::checkGetAllPackages(std::vector<std::string> expectedPackages)
{
    std::vector<std::string> packages;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAllPackages(packages));
    std::sort(packages.begin(), packages.end());
    std::sort(expectedPackages.begin(), expectedPackages.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(packages.begin(), packages.end(),
    expectedPackages.begin(), expectedPackages.end());
};

void PrivilegeDBGettersFixture::checkGetAuthorIdByName(const std::string &authorName,
        int expectedAuthorId)
{
    int authorId;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAuthorIdByName(authorName, authorId));
    BOOST_CHECK_MESSAGE(expectedAuthorId == authorId, "GetAuthorIdByName for authorName: "
        << authorName << " returned wrong authorId: " << authorId << " expected: "
        << expectedAuthorId);
};

void PrivilegeDBGettersFixture::checkGetPkgApps(const std::string &package,
        std::vector<std::string> expectedApps)
{
    std::vector<std::string> apps;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPkgApps(package, apps));
    std::sort(apps.begin(), apps.end());
    std::sort(expectedApps.begin(), expectedApps.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(apps.begin(), apps.end(),
        expectedApps.begin(), expectedApps.end());
};

void PrivilegeDBGettersFixture::checkGetPkgAuthorId(const std::string &pkgName,
        int expectedAuthorId)
{
    int authorId;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPkgAuthorId(pkgName, authorId));
    BOOST_CHECK_MESSAGE(expectedAuthorId == authorId, "GetPkgAuthorId for package: "
        << pkgName << " returned authorId: " << authorId << " expected: " << expectedAuthorId);
};

void PrivilegeDBGettersFixture::checkGetUserApps(const uid_t uid,
        std::vector<std::string> expectedApps)
{
    std::vector<std::string> apps;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetUserApps(uid, apps));
    std::sort(apps.begin(), apps.end());
    std::sort(expectedApps.begin(), expectedApps.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(apps.begin(), apps.end(),
        expectedApps.begin(), expectedApps.end());
};

void PrivilegeDBGettersFixture::checkGetUserPkgs(const uid_t uid,
        std::vector<std::string> expectedPkgs)
{
    std::vector<std::string> pkgs;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetUserPkgs(uid, pkgs));
    std::sort(pkgs.begin(), pkgs.end());
    std::sort(expectedPkgs.begin(), expectedPkgs.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(pkgs.begin(), pkgs.end(),
        expectedPkgs.begin(), expectedPkgs.end());
};

void PrivilegeDBGettersFixture::checkIsPackageHybrid(const std::string &pkgName,
        bool expectedIsHybrid)
{
    bool isHybrid;
    BOOST_REQUIRE_NO_THROW(isHybrid = getPrivDb()->IsPackageHybrid(pkgName));
    BOOST_CHECK_MESSAGE(expectedIsHybrid == isHybrid, "IsPackageHybrid for pkgName: "
        << pkgName << " returned wrong value: " << isHybrid << " expected: "
        << expectedIsHybrid);
};


BOOST_FIXTURE_TEST_SUITE(PRIVILEGE_DB_TEST_GETTERS, PrivilegeDBGettersFixture)

// *Exists, GetApp*

BOOST_AUTO_TEST_CASE(T300_app_name_exists_finds_nothing)
{
    const std::string notAnExistingAppName("notAnExistingAppNameT300");

    BOOST_REQUIRE_MESSAGE(!getPrivDb()->AppNameExists(notAnExistingAppName),
        "AppNameExists wrongly reported " << notAnExistingAppName <<
        " as existing application name");
}

BOOST_AUTO_TEST_CASE(T315_pkg_name_exists_finds_nothing)
{
    const std::string notAnExistingPkgName("notAnExistingPkgNameT310");

    BOOST_REQUIRE_MESSAGE(!getPrivDb()->PkgNameExists(notAnExistingPkgName),
        "PkgNameExists wrongly reported " << notAnExistingPkgName <<
        " as existing package name");
}

BOOST_AUTO_TEST_CASE(T320_author_id_exists_finds_nothing)
{
    //database is clean, author ids are assigned sequentially from bottom
    const int notExistingAuthorId= 200;

    BOOST_REQUIRE_MESSAGE(!getPrivDb()->AuthorIdExists(notExistingAuthorId),
        "AuthorIdExists wrongly reported " << notExistingAuthorId <<
        " as existing author id");
}

BOOST_AUTO_TEST_CASE(T325_app_name_pkg_author_exists)
{
    int authorId;

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(1), tizenVer(1), author(2), NotHybrid);
    addAppSuccess(app(3), pkg(2), uid(1), tizenVer(1), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(2), uid(1), tizenVer(1), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(2), uid(2), tizenVer(1), author(2), NotHybrid);

    BOOST_REQUIRE_MESSAGE(getPrivDb()->AppNameExists(app(1)),
        "AppNameExists wrongly not reported " << app(1) << " as existing application name");
    BOOST_REQUIRE_MESSAGE(getPrivDb()->PkgNameExists(pkg(1)),
        "PkgNameExists wrongly not reported " << pkg(1) << " as existing package name");
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAuthorIdByName(author(1), authorId));
    BOOST_REQUIRE_MESSAGE(getPrivDb()->AuthorIdExists(authorId),
        "AuthorIdExists wrongly not found " << author(1) << " as existing author");
}

BOOST_AUTO_TEST_CASE(T330_get_app_pkg_name)
{
    std::string package1, package2, package3, package4;

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(3), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(3), uid(4), tizenVer(3), author(2), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppPkgName(app(1), package1));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppPkgName(app(2), package2));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppPkgName(app(3), package3));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppPkgName(app(4), package4));

    BOOST_REQUIRE_MESSAGE(package1 == pkg(1), "Expected package name for app: " <<  app(1)
        << " to be: " << pkg(1) << " got: " << package1);
    BOOST_REQUIRE_MESSAGE(package2 == pkg(2), "Expected package name for app: " <<  app(2)
        << " to be: " << pkg(2) << " got: " << package2);
    BOOST_REQUIRE_MESSAGE(package3 == pkg(3), "Expected package name for app: " <<  app(3)
        << " to be: " << pkg(3) << " got: " << package3);
    BOOST_REQUIRE_MESSAGE(package4 == pkg(3), "Expected package name for app: " <<  app(4)
        << " to be: " << pkg(3) << " got: " << package4);
}

BOOST_AUTO_TEST_CASE(T335_get_app_version)
{
    std::string version1, version2, version3, version4;

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(3), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(3), uid(4), tizenVer(3), author(2), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppVersion(app(1), version1));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppVersion(app(2), version2));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppVersion(app(3), version3));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppVersion(app(4), version4));

    BOOST_REQUIRE_MESSAGE(version1 == tizenVer(1), "Expected Tizen version for app: "
        << app(1) << " to be: " << tizenVer(1) << " got: " << version1);
    BOOST_REQUIRE_MESSAGE(version2 == tizenVer(2), "Expected Tizen version for app: "
        << app(2) << " to be: " << tizenVer(2) << " got: " << version2);
    BOOST_REQUIRE_MESSAGE(version3 == tizenVer(3), "Expected Tizen version for app: "
        << app(3) << " to be: " << tizenVer(3) << " got: " << version3);
    BOOST_REQUIRE_MESSAGE(version4 == tizenVer(3), "Expected Tizen version for app: "
        << app(4) << " to be: " << tizenVer(3) << " got: " << version4);
}

BOOST_AUTO_TEST_CASE(T340_get_app_package_finds_nothing)
{
    std::string package;

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppPkgName(app(2), package));
    BOOST_REQUIRE_MESSAGE(package.empty(), "Expected empty string as package of nonexisting app "
        << "got: " << package);
}

BOOST_AUTO_TEST_CASE(T345_get_app_version_finds_nothing)
{
    std::string version;

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAppVersion(app(2), version));
    BOOST_REQUIRE_MESSAGE(version.empty(),
        "Expected empty string as version of nonexisting app got: " << version);
}

// Get*

BOOST_AUTO_TEST_CASE(T350_get_user_apps)
{
    addAppSuccess(app(1), pkg(1), uid(2), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(3), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(3), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(3), uid(3), tizenVer(3), author(2), NotHybrid);
    addAppSuccess(app(5), pkg(4), uid(4), tizenVer(1), author(2), NotHybrid);

    checkGetUserApps(uid(1), {});
    checkGetUserApps(uid(2), {app(1)});
    checkGetUserApps(uid(3), {app(2), app(3), app(4)});
    checkGetUserApps(uid(4), {app(5)});

    removeAppSuccess(app(2), uid(3));
    removeAppSuccess(app(3), uid(3));
    addAppSuccess(app(2), pkg(4), uid(4), tizenVer(1), author(2), NotHybrid);
    addAppSuccess(app(3), pkg(4), uid(4), tizenVer(1), author(2), NotHybrid);

    checkGetUserApps(uid(3), {app(4)});
    checkGetUserApps(uid(4), {app(2), app(3), app(5)});
}

BOOST_AUTO_TEST_CASE(T355_get_user_packages)
{
    addAppSuccess(app(1), pkg(1), uid(2), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(3), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(4), pkg(4), uid(3), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(5), pkg(5), uid(4), tizenVer(1), author(1), NotHybrid);

    checkGetUserPkgs(uid(1), {});
    checkGetUserPkgs(uid(2), {pkg(1)});
    checkGetUserPkgs(uid(3), {pkg(2), pkg(3), pkg(4)});
    checkGetUserPkgs(uid(4), {pkg(5)});

    removeAppSuccess(app(2), uid(3));
    removeAppSuccess(app(3), uid(3));
    addAppSuccess(app(2), pkg(2), uid(4), tizenVer(1), author(2), NotHybrid);
    addAppSuccess(app(3), pkg(3), uid(4), tizenVer(1), author(2), NotHybrid);

    checkGetUserPkgs(uid(3), {pkg(4)});
    checkGetUserPkgs(uid(4), {pkg(2), pkg(3), pkg(5)});
}

BOOST_AUTO_TEST_CASE(T360_get_pkg_apps)
{
    addAppSuccess(app(1), pkg(2), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(3), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(3), pkg(3), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(4), pkg(3), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(5), pkg(4), uid(1), tizenVer(1), author(1), NotHybrid);

    checkGetPkgApps(pkg(1), {});
    checkGetPkgApps(pkg(2), {app(1)});
    checkGetPkgApps(pkg(3), {app(2), app(3), app(4)});
    checkGetPkgApps(pkg(4), {app(5)});

    removeAppSuccess(app(1), uid(1));
    removeAppSuccess(app(2), uid(1));
    removeAppSuccess(app(3), uid(1));
    addAppSuccess(app(1), pkg(4), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(4), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(3), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    checkGetPkgApps(pkg(1), {app(3)});
    checkGetPkgApps(pkg(2), {});
    checkGetPkgApps(pkg(3), {app(4)});
    checkGetPkgApps(pkg(4), {app(1), app(2), app(5)});
}

BOOST_AUTO_TEST_CASE(T365_get_all_packages)
{
    checkGetAllPackages({});

    addAppSuccess(app(1), pkg(2), uid(1), tizenVer(1), author(1), NotHybrid);
    checkGetAllPackages({pkg(2)});

    addAppSuccess(app(2), pkg(3), uid(1), tizenVer(1), author(1), NotHybrid);
    checkGetAllPackages({pkg(2), pkg(3)});

    addAppSuccess(app(3), pkg(3), uid(1), tizenVer(1), author(1), NotHybrid);
    checkGetAllPackages({pkg(2), pkg(3)});

    addAppSuccess(app(4), pkg(3), uid(1), tizenVer(1), author(1), NotHybrid);
    checkGetAllPackages({pkg(2), pkg(3)});

    addAppSuccess(app(5), pkg(4), uid(1), tizenVer(1), author(1), NotHybrid);
    checkGetAllPackages({pkg(2), pkg(3), pkg(4)});

    removeAppSuccess(app(1), uid(1));
    checkGetAllPackages({pkg(3), pkg(4)});

    removeAppSuccess(app(2), uid(1));
    checkGetAllPackages({pkg(3), pkg(4)});

    removeAppSuccess(app(3), uid(1));
    removeAppSuccess(app(4), uid(1));
    checkGetAllPackages({pkg(4)});

    addAppSuccess(app(1), pkg(4), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(4), uid(1), tizenVer(1), author(1), NotHybrid);
    checkGetAllPackages({pkg(4)});

    addAppSuccess(app(3), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    checkGetAllPackages({pkg(1), pkg(4)});
}

BOOST_AUTO_TEST_CASE(T370_get_pkg_author_id)
{
    checkGetPkgAuthorId(pkg(1), -1);

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    checkGetPkgAuthorId(pkg(1), 1);

    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(1), author(2), Hybrid);
    checkGetPkgAuthorId(pkg(2), 2);

    addAppSuccess(app(3), pkg(2), uid(2), tizenVer(1), author(2), Hybrid);
    checkGetPkgAuthorId(pkg(2), 2);

    removeAppSuccess(app(1), uid(1));
    checkGetPkgAuthorId(pkg(1), -1);

    addAppSuccess(app(1), pkg(1), uid(3), tizenVer(1), author(3), Hybrid);
    checkGetPkgAuthorId(pkg(1), 3);
}

BOOST_AUTO_TEST_CASE(T375_get_pkg_author_id_by_name)
{
    checkGetAuthorIdByName(author(1), -1);

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    checkGetAuthorIdByName(author(1), 1);

    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(1), author(2), NotHybrid);
    checkGetAuthorIdByName(author(2), 2);

    removeAppSuccess(app(1), uid(1));
    checkGetAuthorIdByName(author(1), -1);

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    checkGetAuthorIdByName(author(1), 3);
}

BOOST_AUTO_TEST_CASE(T380_is_package_Hybrid)
{
    checkIsPackageHybrid(pkg(1), NotHybrid);

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    checkIsPackageHybrid(pkg(1), NotHybrid);

    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(1), author(2), NotHybrid);
    checkIsPackageHybrid(pkg(2), NotHybrid);

    addAppSuccess(app(3), pkg(3), uid(1), tizenVer(1), author(1), Hybrid);
    checkIsPackageHybrid(pkg(3), Hybrid);
}

BOOST_AUTO_TEST_SUITE_END()
