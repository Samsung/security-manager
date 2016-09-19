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
 * @file       test_file-lock.cpp
 * @author     Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version    1.0
 */
#define BOOST_TEST_MODULE SecurityManagerTest
#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include <cstdio>
#include <string>

#include <dpl/errno_string.h>
#include <dpl/log/log.h>
#include <file-lock.h>

using namespace SecurityManager;

struct FileLockFixture
{
    FileLockFixture()
    {
        FILE *f;
        f= fopen(existingLockFile.c_str(), "w");
        if (f != NULL)
            fclose(f);
        else
            LogError("Failed to open file " << existingLockFile << " : " << GetErrnoString());
        remove(noExistingLockFile.c_str());

    }

    ~FileLockFixture()
    {
        if (remove(existingLockFile.c_str()))
            LogWarning("Failed to remove file " << existingLockFile << " : " << GetErrnoString());
        remove(noExistingLockFile.c_str());
    }

    const static std::string existingLockFile;
    const static std::string noExistingLockFile;
};

const std::string FileLockFixture::existingLockFile = "/tmp/SecurityManagerUTFileLockExisting";
const std::string FileLockFixture::noExistingLockFile = "/tmp/SecurityManagerUTFileLockNoExisting";


BOOST_AUTO_TEST_SUITE(FILE_LOCK_TEST)

BOOST_FIXTURE_TEST_CASE(T010_empty_file_name, FileLockFixture)
{
    BOOST_REQUIRE_THROW(FileLocker fl(""), FileLocker::Exception::LockFailed);
}

BOOST_FIXTURE_TEST_CASE(T020_existing_file_name, FileLockFixture)
{
    BOOST_REQUIRE_NO_THROW(FileLocker fl(FileLockFixture::existingLockFile));
}

BOOST_FIXTURE_TEST_CASE(T030_no_existing_file_name, FileLockFixture)
{
    BOOST_REQUIRE_NO_THROW(FileLocker fl(FileLockFixture::noExistingLockFile));
}

BOOST_FIXTURE_TEST_CASE(T040_new_lock_file_is_locked, FileLockFixture)
{
    FileLocker fl(std::string(FileLockFixture::existingLockFile), false);
    BOOST_REQUIRE_MESSAGE(fl.Locked(), "New lock file is not locked");
}

BOOST_FIXTURE_TEST_CASE(T050_after_unlock_file_is_unlocked, FileLockFixture)
{
    FileLocker fl(FileLockFixture::noExistingLockFile, false);
    fl.Unlock();
    BOOST_REQUIRE_MESSAGE(not(fl.Locked()), "File is locked after Unlock()");
}

BOOST_FIXTURE_TEST_CASE(T060_after_lock_file_is_locked_again, FileLockFixture)
{
    FileLocker fl(FileLockFixture::existingLockFile, false);
    fl.Unlock();
    fl.Lock();
    BOOST_REQUIRE_MESSAGE(fl.Locked(), "File is locked after Unlock()");
}

BOOST_AUTO_TEST_SUITE_END()
