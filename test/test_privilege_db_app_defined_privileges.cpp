/*
 *  Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

/**
 * @file       test_privilege_db_app_defined_privileges.cpp
 * @author     Dariusz Michaluk (d.michaluk@samsung.com)
 * @version    1.0
 */

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

#include "privilege_db.h"
#include "privilege_db_fixture.h"
#include "security-manager-types.h"

namespace {

struct AppDefinedPrivilegeFixture : public PrivilegeDBFixture {
    void checkAppDefinedPrivileges(const std::string &app, uid_t uid,
                                   const AppDefinedPrivilegesVector &expected);
    void checkClientLicense(const std::string &app, uid_t uid,
                            const std::vector<std::string> &privileges,
                            const std::vector<std::pair<bool, std::string>> &expected);
};

void AppDefinedPrivilegeFixture::checkAppDefinedPrivileges(const std::string &app, uid_t uid,
                                                           const AppDefinedPrivilegesVector &expected)
{
    AppDefinedPrivilegesVector privileges;
    testPrivDb->GetAppDefinedPrivileges(app, uid, privileges);
    BOOST_REQUIRE_MESSAGE(privileges.size() == expected.size(), "Vector sizes differ");

    for (unsigned int i = 0; i < privileges.size(); ++i) {
        BOOST_REQUIRE(std::get<0>(privileges[i]) == std::get<0>(expected[i]));
        BOOST_REQUIRE(std::get<1>(privileges[i]) == std::get<1>(expected[i]));
        BOOST_REQUIRE(std::get<2>(privileges[i]) == std::get<2>(expected[i]));
    }
}

void AppDefinedPrivilegeFixture::checkClientLicense(const std::string &app, uid_t uid,
                                                    const std::vector<std::string> &privileges,
                                                    const std::vector<std::pair<bool, std::string>> &expected)
{
    BOOST_REQUIRE_MESSAGE(privileges.size() == expected.size(), "Vector sizes differ");

    for (unsigned int i = 0; i < privileges.size(); ++i) {
        std::string license;
        BOOST_REQUIRE(expected[i].first == testPrivDb->GetLicenseForClientPrivilege(app, uid, privileges[i], license));
        BOOST_REQUIRE(license == expected[i].second);
    }
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(PRIVILEGE_DB_TEST_APP_DEFINED_PRIVILEGES, AppDefinedPrivilegeFixture)

BOOST_AUTO_TEST_CASE(T1300_app_defined_privileges)
{
    // add some privileges
    AppDefinedPrivilegesVector privileges;
    privileges.push_back(std::make_tuple("org.tizen.my_app.gps",
                                         SM_APP_DEFINED_PRIVILEGE_TYPE_UNTRUSTED,
                                         ""));
    privileges.push_back(std::make_tuple("org.tizen.my_app.sso",
                                         SM_APP_DEFINED_PRIVILEGE_TYPE_LICENSED,
                                         "/opt/data/my_app/res/license"));

    // non-existing application
    checkAppDefinedPrivileges(app(1), uid(1), {});

    // add first application
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);

    // privileges not defined
    checkAppDefinedPrivileges(app(1), uid(1), {});

    // add privilege to non-existing application
    BOOST_REQUIRE_THROW(testPrivDb->AddAppDefinedPrivilege(app(2), uid(1), privileges[0]),
                        PrivilegeDb::Exception::ConstraintError);

    // first application defines first privilege
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddAppDefinedPrivilege(app(1), uid(1), privileges[0]));

    // privilege already defined
    BOOST_REQUIRE_THROW(testPrivDb->AddAppDefinedPrivilege(app(1), uid(1), privileges[0]),
                        PrivilegeDb::Exception::ConstraintError);

    // check non-existing privilege
    std::string appName, license;
    BOOST_REQUIRE_NO_THROW(
        testPrivDb->GetAppAndLicenseForAppDefinedPrivilege(uid(1), std::get<0>(privileges[1]),
                                                           appName, license));
    BOOST_REQUIRE(appName.empty());
    BOOST_REQUIRE(license.empty());

    // first application defines second privilege
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddAppDefinedPrivilege(app(1), uid(1), privileges[1]));

    // check existing privilege application name
    BOOST_REQUIRE_NO_THROW(
        testPrivDb->GetAppAndLicenseForAppDefinedPrivilege(uid(1), std::get<0>(privileges[1]),
                                                           appName, license));
    BOOST_REQUIRE(appName == app(1));
    BOOST_REQUIRE(license == std::get<2>(privileges[1]));

    // check first application privileges
    checkAppDefinedPrivileges(app(1), uid(1), privileges);

    // add second application
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(1), author(2), Hybrid);

    // privilege already defined by first application
    BOOST_REQUIRE_THROW(testPrivDb->AddAppDefinedPrivilege(app(2), uid(2), privileges[0]),
                        PrivilegeDb::Exception::ConstraintError);

    // remove first application privileges
    BOOST_REQUIRE_NO_THROW(testPrivDb->RemoveAppDefinedPrivileges(app(1), uid(1)));
    checkAppDefinedPrivileges(app(1), uid(1), {});

    // uninstall first application and check privileges
    removeAppSuccess(app(1), uid(1));
    checkAppDefinedPrivileges(app(1), uid(1), {});

    // second application defines privileges
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddAppDefinedPrivilege(app(2), uid(2), privileges[0]));
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddAppDefinedPrivilege(app(2), uid(2), privileges[1]));
    checkAppDefinedPrivileges(app(2), uid(2), privileges);

    // install second application for different user and add privileges
    addAppSuccess(app(2), pkg(2), uid(3), tizenVer(1), author(2), Hybrid);
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddAppDefinedPrivilege(app(2), uid(3), privileges[0]));
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddAppDefinedPrivilege(app(2), uid(3), privileges[1]));
    checkAppDefinedPrivileges(app(2), uid(3), privileges);

    // uninstall second application and check privileges
    removeAppSuccess(app(2), uid(2));
    checkAppDefinedPrivileges(app(2), uid(2), {});
    checkAppDefinedPrivileges(app(2), uid(3), privileges);

    removeAppSuccess(app(2), uid(3));
    checkAppDefinedPrivileges(app(2), uid(2), {});
    checkAppDefinedPrivileges(app(2), uid(3), {});
}

BOOST_AUTO_TEST_CASE(T1400_client_license)
{
    // add some privileges/licenses
    std::vector<std::pair<std::string, std::string>> privilegesA, privilegesB;
    privilegesA.push_back(std::make_pair("org.tizen.first_app.gps",
                                         "/opt/data/client_appA/res/first_app_client_license"));
    privilegesA.push_back(std::make_pair("org.tizen.second_app.sso",
                                         "/opt/data/client_appA/res/second_app_client_license"));
    privilegesB.push_back(std::make_pair("org.tizen.first_app.gps",
                                         "/opt/data/client_appB/res/first_app_client_license"));
    privilegesB.push_back(std::make_pair("org.tizen.second_app.sso",
                                         "/opt/data/client_appB/res/second_app_client_license"));

    // non-existing application
    checkClientLicense(app(1), uid(1), {privilegesA[0].first}, {{false, ""}});

    // add application
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), Hybrid);

    // privileges/licenses not used
    checkClientLicense(app(1), uid(1), {privilegesA[0].first}, {{false, ""}});

    // add privilege/license to non-existing application
    BOOST_REQUIRE_THROW(testPrivDb->AddClientPrivilege(app(2), uid(1), privilegesA[0].first, privilegesA[0].second),
                        PrivilegeDb::Exception::ConstraintError);

    // first application use first privilege/license
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddClientPrivilege(app(1), uid(1), privilegesA[0].first, privilegesA[0].second));

    // privilege license already defined
    BOOST_REQUIRE_THROW(testPrivDb->AddClientPrivilege(app(1), uid(1), privilegesA[0].first, privilegesA[1].second),
                        PrivilegeDb::Exception::ConstraintError);

    // check non-existing privilege
    std::string license;
    BOOST_REQUIRE_NO_THROW(testPrivDb->GetLicenseForClientPrivilege(app(1), uid(1), privilegesA[1].first, license));
    BOOST_REQUIRE(license.empty());

    // first application use second privilege/license
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddClientPrivilege(app(1), uid(1), privilegesA[1].first, privilegesA[1].second));

    // check existing privilege license
    checkClientLicense(app(1), uid(1), {privilegesA[0].first, privilegesA[1].first},
                       {{true, privilegesA[0].second}, {true, privilegesA[1].second}});

    // add second application
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(1), author(2), Hybrid);

    // privileges/licenses not used
    checkClientLicense(app(2), uid(2), {privilegesA[0].first}, {{false, ""}});

    // second application use first privilege/license
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddClientPrivilege(app(2), uid(2), privilegesB[0].first, privilegesB[0].second));

    // check non-existing privilege
    BOOST_REQUIRE_NO_THROW(testPrivDb->GetLicenseForClientPrivilege(app(2), uid(2), privilegesB[1].first, license));
    BOOST_REQUIRE(license.empty());

    // second application use second privilege/license
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddClientPrivilege(app(2), uid(2), privilegesB[1].first, privilegesB[1].second));

    // check existing privilege/license
    checkClientLicense(app(2), uid(2), {privilegesB[0].first, privilegesB[1].first},
                       {{true, privilegesB[0].second}, {true, privilegesB[1].second}});

    // remove first application privileges/licenses
    BOOST_REQUIRE_NO_THROW(testPrivDb->RemoveClientPrivileges(app(1), uid(1)));
    checkClientLicense(app(1), uid(1), {privilegesA[0].first, privilegesA[1].first},
                       {{false, ""}, {false, ""}});

    // install second application for different user and add privileges
    addAppSuccess(app(2), pkg(2), uid(3), tizenVer(1), author(2), Hybrid);
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddClientPrivilege(app(2), uid(3), privilegesB[0].first, privilegesB[0].second));
    BOOST_REQUIRE_NO_THROW(testPrivDb->AddClientPrivilege(app(2), uid(3), privilegesB[1].first, privilegesB[1].second));
    checkClientLicense(app(2), uid(3), {privilegesB[0].first, privilegesB[1].first},
                       {{true, privilegesB[0].second}, {true, privilegesB[1].second}});

    // uninstall second application and check privileges/licenses
    removeAppSuccess(app(2), uid(2));
    checkClientLicense(app(2), uid(2), {privilegesB[0].first, privilegesB[1].first},
                       {{false, ""}, {false, ""}});

    removeAppSuccess(app(2), uid(3));
    checkClientLicense(app(2), uid(3), {privilegesB[0].first, privilegesB[1].first},
                       {{false, ""}, {false, ""}});
}

BOOST_AUTO_TEST_SUITE_END()
