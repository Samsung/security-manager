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
 * @file       test_privilege_db_add_app.cpp
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include "privilege_db.h"
#include "privilege_db_fixture.h"

BOOST_FIXTURE_TEST_SUITE(PRIVILEGE_DB_TEST_ADD_APP, PrivilegeDBFixture)

// AddApplication

BOOST_AUTO_TEST_CASE(T400_add_application_simple)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T410_add_application_empty_name)
{
    addAppSuccess("", pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T420_add_application_long_name)
{
    const std::string app("IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongString"
        "IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongStringappNT420");

    addAppSuccess(app, pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T430_add_application_name_with_spaces)
{
    const std::string app("appN1 with spaces T430");

    addAppSuccess(app, pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T440_add_application_empty_pkg_name)
{
    addAppSuccess(app(1), "", uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T450_add_application_long_pkg_name)
{
    const std::string pkg("IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongString"
        "IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongStringpkg(1)T450");

    addAppSuccess(app(1), pkg, uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T460_add_application_name_with_spaces_pkg)
{
    const std::string pkg("pkgN with spaces T460");

    addAppSuccess(app(1), pkg, uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T470_add_application_empty_tizenVer)
{
    addAppSuccess(app(1), pkg(1), uid(1), "", author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T480_add_application_long_tizenVer)
{
    const std::string tizenVer("IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongString"
        "IAmAVeryLongStringIAmAVeryLongStringIAmAVeryLongStringtizenN1T480");

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer, author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T490_add_application_tizenVer_with_spaces)
{
    const std::string tizenVer("tizenVer with spaces T490");

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer, author(1), Hybrid);
}
BOOST_AUTO_TEST_CASE(T500_add_application_twice_to_same_package)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T510_add_application_to_different_packages)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    addAppFail(app(1), pkg(2), uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T520_add_application_two_tizen_versions_to_same_package)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(2), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T530_add_application_two_tizen_versions_to_two_packages)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppFail(app(1), pkg(2), uid(1), tizenVer(2), author(1), NotHybrid);
}

BOOST_AUTO_TEST_CASE(T540_add_application_different_Hybrid_to_package)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppFail(app(1), pkg(1), uid(2), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T550_add_application_same_name)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    addAppFail(app(1), pkg(2), uid(2), tizenVer(2), author(2), NotHybrid);
}

BOOST_AUTO_TEST_CASE(T560_add_five_applications_to_same_package)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    addAppSuccess(app(2), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    addAppSuccess(app(3), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    addAppSuccess(app(4), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    addAppSuccess(app(5), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
}

BOOST_AUTO_TEST_CASE(T570_add_applications_with_different_author_to_package)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppFail(app(2), pkg(1), uid(1), tizenVer(1), author(2), NotHybrid);
    BOOST_REQUIRE_MESSAGE(!getPrivDb()->AppNameExists(app(2)),
        "AppNameExists wrongly reported " << app(2) << " as existing application name");
}

BOOST_AUTO_TEST_CASE(T580_add_applications_with_different_authors_to_packages)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(3), pkg(2), uid(1), tizenVer(1), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(2), uid(1), tizenVer(1), author(2), NotHybrid);
}

BOOST_AUTO_TEST_CASE(T590_add_applications_with_empty_noempty_author)
{
    int authorIdPkg;
    int authorId;

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), "", NotHybrid);
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPkgAuthorId(pkg(1), authorIdPkg));
    BOOST_REQUIRE_MESSAGE(authorIdPkg == -1, "Wrong author id returned: " << authorIdPkg
        << " expected: -1");

    addAppSuccess(app(2), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPkgAuthorId(pkg(1), authorIdPkg));
    BOOST_REQUIRE_MESSAGE(authorIdPkg != -1, "Wrong author id returned: -1");
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetAuthorIdByName(author(1), authorId));
    BOOST_REQUIRE_MESSAGE(authorId == authorIdPkg, "Author id returned by GetAuthorIdByName: "
        << authorId << " does not match author id returned by GetPkgAuthorId: " << authorIdPkg);

    addAppSuccess(app(3), pkg(1), uid(1), tizenVer(1), "", NotHybrid);
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPkgAuthorId(pkg(2), authorIdPkg));
    BOOST_REQUIRE_MESSAGE(authorIdPkg == -1, "Wrong author id returned: " << authorIdPkg
        << " expected: -1");
}

BOOST_AUTO_TEST_CASE(T600_add_applications_with_different_isHybrid_false_true)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppFail(app(2), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    BOOST_REQUIRE_MESSAGE(!getPrivDb()->AppNameExists(app(2)),
        "AppNameExists wrongly reported " << app(2) << " as existing application name");
}

BOOST_AUTO_TEST_CASE(T610_add_applications_with_different_isHybrid_true_false)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);
    addAppFail(app(2), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    BOOST_REQUIRE_MESSAGE(!getPrivDb()->AppNameExists(app(2)),
        "AppNameExists wrongly reported " << app(2) << " as existing application name");
}

BOOST_AUTO_TEST_CASE(T620_add_applications_with_different_isHybrid_to_two_packages)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(3), pkg(2), uid(1), tizenVer(1), author(2), Hybrid);
    addAppSuccess(app(4), pkg(2), uid(1), tizenVer(1), author(2), Hybrid);
}

BOOST_AUTO_TEST_CASE(T630_add_applications_with_different_uid_to_package)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(1), pkg(1), uid(2), tizenVer(1), author(1), NotHybrid);
}

BOOST_AUTO_TEST_CASE(T640_add_applications_with_different_uid_to_two_packages)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppFail(app(1), pkg(2), uid(2), tizenVer(1), author(1), NotHybrid);
}

BOOST_AUTO_TEST_SUITE_END()
