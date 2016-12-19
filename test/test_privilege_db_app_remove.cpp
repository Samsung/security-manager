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
 * @file       test_privilege_db_app_remove.cpp
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */

#include <stdlib.h>
#include <string>
#include <sys/types.h>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include "privilege_db.h"
#include "privilege_db_fixture.h"

BOOST_FIXTURE_TEST_SUITE(PRIVILEGE_DB_TEST_APP_REMOVE, PrivilegeDBFixture)

// RemoveApplication

BOOST_AUTO_TEST_CASE(T700_add_remove_add_application)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    removeApp(app(1), uid(1), true, true, true);
    addAppSuccess(app(1), pkg(2), uid(1), tizenVer(1), author(1), NotHybrid);
}

BOOST_AUTO_TEST_CASE(T710_add_double_remove_add_application)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    removeApp(app(1), uid(1), true, true, true);
    removeApp(app(1), uid(1), false, false, false);
    addAppSuccess(app(1), pkg(2), uid(1), tizenVer(1), author(1), NotHybrid);
}

BOOST_AUTO_TEST_CASE(T720_add_remove_application_to_different_users)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(1), pkg(1), uid(2), tizenVer(1), author(1), NotHybrid);
    removeApp(app(1), uid(1), false, false, false);
    removeApp(app(1), uid(2), true, true, true);
}

BOOST_AUTO_TEST_CASE(T730_app_name_pkg_author_exists_with_remove)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(3), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(3), uid(4), tizenVer(3), author(2), NotHybrid);

    removeApp(app(1), uid(1), true, true, true);
    removeApp(app(3), uid(3), true, false, false);
    removeApp(app(4), uid(4), true, true, false);
    removeApp(app(4), uid(4), false, false, false);
    removeApp(app(2), uid(2), true, true, true);

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(3), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(3), uid(4), tizenVer(3), author(2), NotHybrid);
    addAppSuccess(app(5), pkg(4), uid(4), tizenVer(1), author(2), NotHybrid);

    removeApp(app(1), uid(2), false, false, false);
    removeApp(app(1), uid(1), true, true, true);
    removeApp(app(2), uid(2), true, true, false);
    removeApp(app(3), uid(3), true, false, false);
    removeApp(app(4), uid(4), true, true, false);
    removeApp(app(5), uid(4), true, true, true);
}

BOOST_AUTO_TEST_CASE(T740_remove_application_with_no_effect)
{
    removeAppSuccess(app(1), uid(1));
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(1), author(1), NotHybrid);
    removeApp(app(2), uid(1), false, false, false);  //uid(1) != uid(2)
    BOOST_REQUIRE_MESSAGE(getPrivDb()->AppNameExists(app(2)),
        "AppNameExists wrongly not reported " << app(2) << " as existing application name");
}

BOOST_AUTO_TEST_SUITE_END()
