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
 * @file       test_privilege_db_sharing.cpp
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */

#include <ostream>
#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>
#include <boost/test/utils/wrap_stringstream.hpp>

#include "privilege_db.h"
#include "privilege_db_fixture.h"

#if BOOST_VERSION >= 105900

namespace boost {

namespace test_tools {

namespace tt_detail {

// tell boost howto print pair of std::string and std::vector
template<typename T, typename U>
struct print_log_value<std::pair<T, std::vector<U>>> {
    void operator()(std::ostream& os, std::pair<T, std::vector<U>> const& pr) {
        os << "<" << std::get<0>(pr) << ",";
        os << '[';
        bool first = true;
        for (auto &element : std::get<1>(pr)) {
            os << (!first ? "," : "") << element;
            first = false;
        }
	os << ']';
    }
};

} //namespace tt_detail

} //namespace test_tools

} //namespace boost

#else

namespace boost
{

// tell Boost.Test how to print std::vector
template <typename T>
inline wrap_stringstream&
operator<<(wrap_stringstream &wrapped, const std::vector<T> &item)
{
    wrapped << '[';
    bool first = true;
    for (const auto& element : item) {
        wrapped << (!first ? "," : "") << element;
        first = false;
    }
    return wrapped << ']';
}

// teach Boost.Test how to print std::pair<K,V>
template <typename T, typename V>
inline wrap_stringstream &operator<<(wrap_stringstream &wrapped, const std::pair<T, V> &item)
{
    return wrapped << '<' << item.first << ',' << item.second << '>';
}

} //namespace boost

#endif

typedef std::map<std::string, std::vector<std::string>> PrivateSharingMap;

//Fixture for sharing

struct PrivilegeDBSharingFixture : PrivilegeDBFixture
{
    void checkAllPrivateSharing(PrivateSharingMap expectedAppPathMap);
    void checkPrivateSharingForOwner(const std::string &ownerAppName,
        PrivateSharingMap expectedOwnerSharing);
    void checkPrivateSharingForTarget(const std::string &targetAppName,
        PrivateSharingMap expectedTargetSharing);
    void checkClearPrivateSharingForApp(const std::string &appName);
};

void PrivilegeDBSharingFixture::checkAllPrivateSharing(PrivateSharingMap expectedAppPathMap)
{
    PrivateSharingMap appPathMap;

    BOOST_REQUIRE_NO_THROW(testPrivDb->GetAllPrivateSharing(appPathMap));
    BOOST_REQUIRE_MESSAGE(appPathMap.size() == expectedAppPathMap.size(), "Result size; "
        << appPathMap.size() << " does not match expected size: " << expectedAppPathMap.size());
    for (auto &v : appPathMap)
        std::sort(v.second.begin(), v.second.end());
    for (auto &v : expectedAppPathMap)
        std::sort(v.second.begin(), v.second.end());

    BOOST_CHECK_EQUAL_COLLECTIONS(appPathMap.begin(), appPathMap.end(),
    expectedAppPathMap.begin(), expectedAppPathMap.end());
};

void PrivilegeDBSharingFixture::checkPrivateSharingForOwner(const std::string &ownerAppName,
    PrivateSharingMap expectedOwnerSharing)
{
    PrivateSharingMap ownerSharing;

    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPrivateSharingForOwner(ownerAppName,
        ownerSharing));
    BOOST_CHECK_MESSAGE(ownerSharing.size() == expectedOwnerSharing.size(), "Result size; "
        << ownerSharing.size() << " does not match expected size: "
        << expectedOwnerSharing.size());

    for (auto &v : ownerSharing)
        std::sort(v.second.begin(), v.second.end());
    for (auto &v : expectedOwnerSharing)
        std::sort(v.second.begin(), v.second.end());

    BOOST_CHECK_EQUAL_COLLECTIONS(ownerSharing.begin(), ownerSharing.end(),
    expectedOwnerSharing.begin(), expectedOwnerSharing.end());
};

void PrivilegeDBSharingFixture::checkPrivateSharingForTarget(const std::string &targetAppName,
        PrivateSharingMap expectedTargetSharing)
{
    PrivateSharingMap targetSharing;

    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPrivateSharingForTarget(targetAppName,
        targetSharing));
    BOOST_CHECK_MESSAGE(targetSharing.size() == expectedTargetSharing.size(), "Result size; "
        << targetSharing.size() << " does not match expected size: "
        << expectedTargetSharing.size());

    for (auto &v : targetSharing)
        std::sort(v.second.begin(), v.second.end());
    for (auto &v : expectedTargetSharing)
        std::sort(v.second.begin(), v.second.end());

    BOOST_CHECK_EQUAL_COLLECTIONS(targetSharing.begin(), targetSharing.end(),
    expectedTargetSharing.begin(), expectedTargetSharing.end());
};

void PrivilegeDBSharingFixture::checkClearPrivateSharingForApp(const std::string &appName)
{
    PrivateSharingMap ownerInfo;
    PrivateSharingMap targetInfo;

    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPrivateSharingForOwner(appName, ownerInfo));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPrivateSharingForTarget(appName, targetInfo));

    BOOST_CHECK_MESSAGE(ownerInfo.size() == 0, "Result size (GetPrivateSharingForOwner); "
        << ownerInfo.size() << " does not match expected size: 0");
    BOOST_CHECK_MESSAGE(targetInfo.size() == 0, "Result size (GetPrivateSharingForTarget); "
        << targetInfo.size() << " does not match expected size: 0");
};

BOOST_FIXTURE_TEST_SUITE(PRIVILEGE_DB_TEST_SHARING, PrivilegeDBSharingFixture)

// Path sharing

BOOST_AUTO_TEST_CASE(T900_get_path_sharing_count_from_empty_db)
{
    int count;

    BOOST_REQUIRE_NO_THROW(getPrivDb()->GetPathSharingCount(path(1), count));
    BOOST_REQUIRE_MESSAGE(count == 0, "GetPathSharingCount found some sharing in empty database");
}

BOOST_AUTO_TEST_CASE(T910_apply_private_sharing)
{

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    checkPrivateSharing(app(1), app(2), path(1), 0, 0, 0);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    checkPrivateSharing(app(1), app(2), path(1), 1, 1, 1);

    addAppSuccess(app(3), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(4), pkg(4), uid(2), tizenVer(2), author(2), Hybrid);
    checkPrivateSharing(app(1), app(2), path(1), 1, 1, 1);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    checkPrivateSharing(app(1), app(2), path(1), 1, 1, 1);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(2), lab(2)));
    checkPrivateSharing(app(1), app(2), path(2), 1, 2, 1);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(1), path(3), lab(3)));
    checkPrivateSharing(app(2), app(1), path(3), 1, 1, 1);
    checkPrivateSharing(app(1), app(2), path(3), 1, 2, 0);
}

BOOST_AUTO_TEST_CASE(T920_apply_private_sharing_same_path_different_owners)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(3), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    BOOST_REQUIRE_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(2), path(1), lab(1)),
        PrivilegeDb::Exception::ConstraintError);
    checkPrivateSharing(app(1), app(2), path(1), 1, 1, 1);
}

BOOST_AUTO_TEST_CASE(T930_apply_private_sharing_same_path_different_label)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(3), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    BOOST_REQUIRE_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(3), path(1), lab(2)),
        PrivilegeDb::Exception::ConstraintError);
    checkPrivateSharing(app(1), app(3), path(1), 1, 0, 0);
}

BOOST_AUTO_TEST_CASE(T940_drop_private_sharing)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(2), author(2), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(3), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(3), path(2), lab(2)));

    checkPrivateSharing(app(1), app(2), path(1), 2, 2, 1);
    checkPrivateSharing(app(1), app(2), path(2), 2, 2, 1);
    checkPrivateSharing(app(1), app(3), path(1), 2, 2, 1);
    checkPrivateSharing(app(1), app(3), path(2), 2, 2, 1);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(1), app(2), path(1)));
    checkPrivateSharing(app(1), app(2), path(1), 1, 1, 0);
    checkPrivateSharing(app(1), app(2), path(2), 2, 1, 1);
    checkPrivateSharing(app(1), app(3), path(1), 1, 2, 1);
    checkPrivateSharing(app(1), app(3), path(2), 2, 2, 1);

    //once more same drop
    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(1), app(2), path(1)));
    checkPrivateSharing(app(1), app(2), path(1), 1, 1, 0);
    checkPrivateSharing(app(1), app(2), path(2), 2, 1, 1);
    checkPrivateSharing(app(1), app(3), path(1), 1, 2, 1);
    checkPrivateSharing(app(1), app(3), path(2), 2, 2, 1);

    //no more path(1)
    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(1), app(3), path(1)));
    checkPrivateSharing(app(1), app(2), path(1), 0, 1, 0);
    checkPrivateSharing(app(1), app(2), path(2), 2, 1, 1);
    checkPrivateSharing(app(1), app(3), path(1), 0, 1, 0);
    checkPrivateSharing(app(1), app(3), path(2), 2, 1, 1);

    //only path(2) (app(1)->app(3)) exists
    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(1), app(2), path(2)));
    checkPrivateSharing(app(1), app(2), path(1), 0, 0, 0);
    checkPrivateSharing(app(1), app(2), path(2), 1, 0, 0);
    checkPrivateSharing(app(1), app(3), path(1), 0, 1, 0);
    checkPrivateSharing(app(1), app(3), path(2), 1, 1, 1);
}

BOOST_AUTO_TEST_CASE(T950_get_all_private_sharing)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(2), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(3), uid(3), tizenVer(2), author(2), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(1), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(3), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(4), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(2), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(3), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(4), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(1), path(3), lab(3)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(2), path(4), lab(4)));
    checkAllPrivateSharing({{app(1), {path(1)}}, {app(2), {path(2)}},
                            {app(3), {path(3), path(4)}}});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(1), app(1), path(2)));
    checkAllPrivateSharing({{app(1), {path(1)}}, {app(2), {path(2)}},
                            {app(3), {path(3), path(4)}}});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(3), app(1), path(3)));
    checkAllPrivateSharing({{app(1), {path(1)}}, {app(2), {path(2)}}, {app(3), {path(4)}}});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(3), app(2), path(4)));
    checkAllPrivateSharing({{app(1), {path(1)}}, {app(2), {path(2)}}});
}

BOOST_AUTO_TEST_CASE(T960_private_sharing_for_owner)
{

    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(2), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(3), uid(3), tizenVer(2), author(2), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(1), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(3), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(4), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(2), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(2), path(4), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(3), path(3), lab(2)));
    checkPrivateSharingForOwner(app(1), {{app(1), {path(1)}}, {app(2), {path(1)}},
        {app(3), {path(1)}}, {app(4), {path(1)}}});
    checkPrivateSharingForOwner(app(2), {{app(2), {path(2), path(4)}}, {app(3), {path(3)}}});
    checkPrivateSharingForOwner(app(3), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(1), app(1), path(1)));
    checkPrivateSharingForOwner(app(1), {{app(2), {path(1)}}, {app(3), {path(1)}},
        {app(4), {path(1)}}});
    checkPrivateSharingForOwner(app(2), {{app(2), {path(2), path(4)}}, {app(3), {path(3)}}});
    checkPrivateSharingForOwner(app(3), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(2), app(2), path(2)));
    checkPrivateSharingForOwner(app(1), {{app(2), {path(1)}}, {app(3), {path(1)}},
        {app(4), {path(1)}}});
    checkPrivateSharingForOwner(app(2), {{app(2), {path(4)}}, {app(3), {path(3)}}});
    checkPrivateSharingForOwner(app(3), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(2), app(2), path(4)));
    checkPrivateSharingForOwner(app(1), {{app(2), {path(1)}}, {app(3), {path(1)}},
        {app(4), {path(1)}}});
    checkPrivateSharingForOwner(app(2), {{app(3), {path(3)}}});
    checkPrivateSharingForOwner(app(3), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(2), app(3), path(3)));
    checkPrivateSharingForOwner(app(1), {{app(2), {path(1)}}, {app(3), {path(1)}}, {app(4), {path(1)}}});
    checkPrivateSharingForOwner(app(2), {});
    checkPrivateSharingForOwner(app(3), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(3), path(3), lab(2)));
    checkPrivateSharingForOwner(app(1), {{app(2), {path(1)}}, {app(3), {path(1)}},
        {app(4), {path(1)}}});
    checkPrivateSharingForOwner(app(2), {{app(3), {path(3)}}});
    checkPrivateSharingForOwner(app(3), {});
}

BOOST_AUTO_TEST_CASE(T970_get_private_sharing_for_target)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(2), author(2), NotHybrid);
    addAppSuccess(app(4), pkg(3), uid(3), tizenVer(2), author(2), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(1), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(1), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(1), path(3), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(1), path(31), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(1), path(32), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(4), app(1), path(4), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(2), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(2), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(3), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(3), path(3), lab(2)));
    checkPrivateSharingForTarget(app(1), {{app(1), {path(1)}}, {app(2), {path(2)}},
        {app(3), {path(3), path(31), path(32)}}, {app(4), {path(4)}}});
    checkPrivateSharingForTarget(app(2), {{app(2), {path(2)}}});
    checkPrivateSharingForTarget(app(3), {{app(2), {path(2)}}, {app(3), {path(3)}}});
    checkPrivateSharingForTarget(app(4), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(1), app(1), path(1)));
    checkPrivateSharingForTarget(app(1), {{app(2), {path(2)}},
        {app(3), {path(3), path(31), path(32)}}, {app(4), {path(4)}}});
    checkPrivateSharingForTarget(app(2), {{app(2), {path(2)}}});
    checkPrivateSharingForTarget(app(3), {{app(2), {path(2)}}, {app(3), {path(3)}}});
    checkPrivateSharingForTarget(app(4), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(2), app(1), path(2)));
    checkPrivateSharingForTarget(app(1), {{app(3), {path(3), path(31), path(32)}}, {app(4),
        {path(4)}}});
    checkPrivateSharingForTarget(app(2), {{app(2), {path(2)}}});
    checkPrivateSharingForTarget(app(3), {{app(2), {path(2)}}, {app(3), {path(3)}}});
    checkPrivateSharingForTarget(app(4), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(3), app(1), path(32)));
    checkPrivateSharingForTarget(app(1), {{app(3), {path(3), path(31)}}, {app(4), {path(4)}}});
    checkPrivateSharingForTarget(app(2), {{app(2), {path(2)}}});
    checkPrivateSharingForTarget(app(3), {{app(2), {path(2)}}, {app(3), {path(3)}}});
    checkPrivateSharingForTarget(app(4), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(3), app(1), path(31)));
    checkPrivateSharingForTarget(app(1), {{app(3), {path(3)}}, {app(4), {path(4)}}});
    checkPrivateSharingForTarget(app(2), {{app(2), {path(2)}}});
    checkPrivateSharingForTarget(app(3), {{app(2), {path(2)}}, {app(3), {path(3)}}});
    checkPrivateSharingForTarget(app(4), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(3), app(1), path(3)));
    checkPrivateSharingForTarget(app(1), {{app(4), {path(4)}}});
    checkPrivateSharingForTarget(app(2), {{app(2), {path(2)}}});
    checkPrivateSharingForTarget(app(3), {{app(2), {path(2)}}, {app(3), {path(3)}}});
    checkPrivateSharingForTarget(app(4), {});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(4), app(1), path(4)));
    checkPrivateSharingForTarget(app(1), {});
    checkPrivateSharingForTarget(app(2), {{app(2), {path(2)}}});
    checkPrivateSharingForTarget(app(3), {{app(2), {path(2)}}, {app(3), {path(3)}}});
    checkPrivateSharingForTarget(app(4), {});
}

BOOST_AUTO_TEST_CASE(T980_squash_private_sharing)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(1), author(1), Hybrid);
    addAppSuccess(app(4), pkg(4), uid(4), tizenVer(2), author(2), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(1), app(2), path(1)));
    checkPrivateSharingForTarget(app(2), {{app(1), {path(1)}}});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(2), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(2), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(4), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(4), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(4), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(4), path(2), lab(2)));
    checkPrivateSharing(app(3), app(4), path(2), 2, 1, 1);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->SquashSharing(app(4), path(2)));
    checkPrivateSharing(app(3), app(4), path(2), 2, 1, 1);
    checkPrivateSharingForTarget(app(2), {{app(1), {path(1)}}, {app(3), {path(2)}}});
    checkPrivateSharingForTarget(app(4), {{app(3), {path(2)}}});

    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(3), app(2), path(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->DropPrivateSharing(app(3), app(4), path(2)));
    checkPrivateSharingForTarget(app(2), {{app(1), {path(1)}}, {app(3), {path(2)}}});
    checkPrivateSharingForTarget(app(4), {});
}

BOOST_AUTO_TEST_CASE(T990_clear_private_sharing)
{
    addAppSuccess(app(1), pkg(1), uid(1), tizenVer(1), author(1), NotHybrid);
    addAppSuccess(app(2), pkg(2), uid(2), tizenVer(2), author(2), Hybrid);
    addAppSuccess(app(3), pkg(3), uid(3), tizenVer(1), author(1), Hybrid);
    addAppSuccess(app(4), pkg(4), uid(4), tizenVer(2), author(2), NotHybrid);

    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(1), app(2), path(1), lab(1)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(1), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(2), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(2), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(3), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(2), app(4), path(2), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(3), app(4), path(3), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ApplyPrivateSharing(app(4), app(1), path(4), lab(2)));
    BOOST_REQUIRE_NO_THROW(getPrivDb()->ClearPrivateSharing());
    checkClearPrivateSharingForApp(app(1));
    checkClearPrivateSharingForApp(app(2));
    checkClearPrivateSharingForApp(app(3));
    checkClearPrivateSharingForApp(app(4));
}

BOOST_AUTO_TEST_SUITE_END()

