/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
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
 * @file        permissible-set.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @author      Radoslaw Bartosiak <r.bartosiak@samsung.com>
 * @version     1.0
 * @brief       Implementation of API for adding, deleting and reading permissible names
 * @brief       (names of installed applications)
 */
#ifndef _GNU_SOURCE //for TEMP_FAILURE_RETRY
#define _GNU_SOURCE
#endif

#include <cstdio>
#include <cstring>
#include <memory>
#include <pwd.h>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <config.h>
#include <dpl/errno_string.h>
#include <dpl/exception.h>
#include <dpl/log/log.h>
#include <permissible-set.h>
#include <privilege_db.h>
#include <security-manager-types.h>
#include <tzplatform_config.h>

typedef std::unique_ptr<FILE, int (*)(FILE *)> filePtr;

namespace SecurityManager {
namespace PermissibleSet {

static filePtr openAndLockNameFile(const std::string &nameFile, const char* mode)
{
    filePtr file(fopen(nameFile.c_str(), mode), fclose);
    if (!file) {
        LogError("Unable to open file" << nameFile << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::FileOpenError, "Unable to open file ");
    }

    int ret = TEMP_FAILURE_RETRY(flock(fileno(file.get()), LOCK_EX));
    if (ret == -1) {
        LogError("Unable to lock file " << nameFile << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::FileLockError, "Unable to lock file");
    }
    return file;
}

std::string getPerrmissibleFileLocation(int installationType)
{
    if ((installationType == SM_APP_INSTALL_GLOBAL)
            || (installationType == SM_APP_INSTALL_PRELOADED))
        return tzplatform_mkpath(TZ_SYS_RW_APP, Config::APPS_NAME_FILE.c_str());
    return tzplatform_mkpath(TZ_USER_APP, Config::APPS_NAME_FILE.c_str());

}

static void markPermissibleFileValid(int fd, const std::string &nameFile, bool valid)
{
    int ret;
    if (valid)
        ret = TEMP_FAILURE_RETRY(fchmod(fd, 00444));
    else
        ret = TEMP_FAILURE_RETRY(fchmod(fd, 00000));
    if (ret == -1) {
        LogError("Error at fchmod " << nameFile << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::FileWriteError, "Error at fchmod");
    }
}

void updatePermissibleFile(uid_t uid, int installationType)
{
    std::string nameFile = getPerrmissibleFileLocation(installationType);
    filePtr file = openAndLockNameFile(nameFile, "w");
    markPermissibleFileValid(fileno(file.get()), nameFile, false);
    std::vector<std::string> appNames;
    PrivilegeDb::getInstance().GetUserApps(uid, appNames);
    for (auto &name : appNames) {
        if (fprintf(file.get(), "%s\n", name.c_str()) < 0) {
            LogError("Unable to fprintf() to file " << nameFile << ": " << GetErrnoString(errno));
            ThrowMsg(PermissibleSetException::PermissibleSetException::FileWriteError,
                    "Unable to fprintf() to file");
        }
    }
    if (fflush(file.get()) != 0) {
        LogError("Error at fflush " << nameFile << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::FileWriteError, "Error at fflush");
    }
    if (fsync(fileno(file.get())) == -1) {
        LogError("Error at fsync " << nameFile << ": " << GetErrnoString(errno));
        ThrowMsg(PermissibleSetException::FileWriteError, "Error at fsync");
    }
    markPermissibleFileValid(fileno(file.get()), nameFile, true);
}

void readNamesFromPermissibleFile(const std::string &nameFile, std::vector<std::string> &names)
{
    filePtr file = openAndLockNameFile(nameFile, "r");
    int ret;
    do {
        char *buf = nullptr;
        std::size_t bufSize = 0;
        switch (ret = getline(&buf, &bufSize, file.get())) {
        case 0:
            continue;
        case -1:
            if (feof(file.get()))
                break;
            LogError("Failure while reading file " << nameFile << ": " << GetErrnoString(errno));
            ThrowMsg(PermissibleSetException::FileReadError, "Failure while reading file");
        default:
            std::unique_ptr<char, decltype(free)*> buf_up(buf, free);
            if (buf[ret - 1] == '\n')
                buf[ret - 1] = '\0';
            names.push_back(buf);
            buf_up.release();
        }
    } while (ret != -1);
}

} // PermissibleSet
} // SecurityManager
