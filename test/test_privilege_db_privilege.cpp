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
 * @file       test_privilege_db_privilege.cpp
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */

#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <utility>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>
#include <boost/test/utils/wrap_stringstream.hpp>

#include "privilege_db.h"
#include "privilege_db_fixture.h"

BOOST_FIXTURE_TEST_SUITE(PRIVILEGE_DB_TEST_PRIVILEGE, PrivilegeDBFixture)

// Privileges

BOOST_AUTO_TEST_CASE(T800_get_groups_from_empty_db)
{
    std::vector<std::string> groups;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetGroups(groups));
    BOOST_REQUIRE_MESSAGE(groups.size() == 0, "GetGroups found some groups in empty database");
}

BOOST_AUTO_TEST_CASE(T810_get_groups)
{
    int ret = system("sqlite3 " TEST_PRIVILEGE_DB_PATH " "
    "\"BEGIN; "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege30', 'group3'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege10', 'group1'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege11', 'group1'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege20', 'group2'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege31', 'group3'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege32', 'group3'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege41', 'group4'); "
    "COMMIT;\" ");
    BOOST_REQUIRE_MESSAGE(ret == 0, "Could not create populate the  database");
    std::vector<std::string> groups;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetGroups(groups));
    std::sort(groups.begin(), groups.end());
    std::vector<std::string> expectedGroups = {"group1", "group2", "group3", "group4"};
    BOOST_CHECK_EQUAL_COLLECTIONS(groups.begin(), groups.end(),
        expectedGroups.begin(), expectedGroups.end());
}

BOOST_AUTO_TEST_CASE(T820_get_groups_related_privileges_from_empty_db)
{
    std::vector<std::pair<std::string, std::string>> privileges;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetGroupsRelatedPrivileges(privileges));
    BOOST_REQUIRE_MESSAGE(privileges.size() == 0, "GetGroupsRelatedPrivileges found some"
        " privileges in empty database");
}

BOOST_AUTO_TEST_CASE(T830_get_groups_related_privileges)
{
    int ret = system("sqlite3 " TEST_PRIVILEGE_DB_PATH " "
    "\"BEGIN; "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege30', 'group3'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege10', 'group1'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege11', 'group1'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege20', 'group2'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege31', 'group3'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege32', 'group3'); "
    "INSERT INTO privilege_group (privilege_name, group_name) VALUES ('privilege41', 'group4'); "
    "COMMIT;\" ");
    BOOST_REQUIRE_MESSAGE(ret == 0, "Could not create populate the  database");
    std::vector<std::pair<std::string, std::string>> privileges;
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetGroupsRelatedPrivileges(privileges));
    std::sort(privileges.begin(), privileges.end(), [](std::pair<std::string, std::string> &a,
                                                       std::pair<std::string, std::string> &b) {
        if (a.first < b.first)
            return true;
        if (b.first < a.first)
            return false;
        if (a.second < b.second)
            return true;
        return false;
    });
    std::vector<std::pair<std::string, std::string>> expectedPrivileges =
            {{"group1", "privilege10"}, {"group1", "privilege11"}, {"group2", "privilege20"},
             {"group3", "privilege30"}, {"group3", "privilege31"}, {"group3", "privilege32"},
             {"group4", "privilege41"}};
    BOOST_REQUIRE_MESSAGE(privileges.size() == expectedPrivileges.size(),
        "GetGroupsRelatedPrivileges returned wrong number of privileges expected: " <<
        expectedPrivileges.size() << " got: " << privileges.size());
    for (unsigned int i = 0; i < privileges.size(); i++)
        BOOST_REQUIRE_MESSAGE(privileges[i] == expectedPrivileges[i], "Expected: ("
             << expectedPrivileges[i].first << "," << expectedPrivileges[i].second << " got: "
             << privileges[i].first << " , " << privileges[i].second << ")");
}

BOOST_AUTO_TEST_SUITE_END()


