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
 * @file       test_privilege_db_transactions.cpp
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */

#include <stdlib.h>
#include <string>
#include <sys/types.h>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>
#include <boost/test/utils/wrap_stringstream.hpp>

#include "privilege_db.h"
#include "privilege_db_fixture.h"


class Empty {}; //to overwrite the suite fixture

BOOST_FIXTURE_TEST_SUITE(PRIVILEGE_DB_TEST_TRANSACTIONS, PrivilegeDBFixture)

// Constructor

BOOST_FIXTURE_TEST_CASE(T100_privilegedb_constructor, Empty)
{
    PrivilegeDb *testPrivDb = nullptr;

    BOOST_REQUIRE_NO_THROW(testPrivDb = new PrivilegeDb());
    delete testPrivDb;
    testPrivDb = nullptr;
    BOOST_REQUIRE_THROW(testPrivDb = new PrivilegeDb("/this/not/exists"),
        PrivilegeDb::Exception::IOError);
    delete testPrivDb;
}

// Transactions

BOOST_AUTO_TEST_CASE(T200_transaction_rollback_commit)
{
    BOOST_REQUIRE_NO_THROW(getPrivDb()->BeginTransaction());
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->RollbackTransaction());
    BOOST_REQUIRE_MESSAGE(!getPrivDb()->AppNameExists(app(1)),
        "AppNameExists wrongly reported " << app(1) << " as existing, despite a rollback");
    BOOST_REQUIRE_THROW(getPrivDb()->CommitTransaction(),
        PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T210_transaction_double_rollback)
{
    BOOST_REQUIRE_NO_THROW(getPrivDb()->BeginTransaction());
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->RollbackTransaction());
    BOOST_REQUIRE_THROW(getPrivDb()->RollbackTransaction(),
        PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T220_commit_without_begin)
{
    BOOST_REQUIRE_THROW(getPrivDb()->CommitTransaction(), PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T230_rollback_without_begin)
{
    BOOST_REQUIRE_THROW(getPrivDb()->RollbackTransaction(), PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T240_transaction)
{
    BOOST_REQUIRE_NO_THROW(getPrivDb()->BeginTransaction());
    addAppSuccess(app(1),pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->CommitTransaction());
    BOOST_REQUIRE_NO_THROW(getPrivDb()->BeginTransaction());
    BOOST_REQUIRE_NO_THROW(getPrivDb()->RollbackTransaction());
    BOOST_REQUIRE_MESSAGE(getPrivDb()->AppNameExists(app(1)),
        "AppNameExists wrongly not reported " << app(1) << " as existing application name");
}

BOOST_AUTO_TEST_CASE(T250_transaction_double_begin)
{
    BOOST_REQUIRE_NO_THROW(getPrivDb()->BeginTransaction());
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    BOOST_REQUIRE_THROW(getPrivDb()->BeginTransaction(),
        PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_CASE(T260_transaction_double_commit)
{
    BOOST_REQUIRE_NO_THROW(getPrivDb()->BeginTransaction());
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->CommitTransaction());
    BOOST_REQUIRE_THROW(getPrivDb()->CommitTransaction(),
        PrivilegeDb::Exception::InternalError);
}

BOOST_AUTO_TEST_SUITE_END()
