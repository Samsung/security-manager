/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        security-manager-cleanup.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of security-manager cleanup service
 */

#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <sys/stat.h>
#include <privilege_db.h>
#include <smack-labels.h>

namespace {
const std::string tmp_flag = "/tmp/sm-cleanup-tmp-flag";

bool fileExists(const std::string &path)
{
    struct stat buffer;
    return stat(path.c_str(), &buffer) == 0 && S_ISREG(buffer.st_mode);
}

bool createFile(const std::string &path)
{
    int fd;
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    fd = TEMP_FAILURE_RETRY(creat(path.c_str(), mode));
    if (fd == -1) {
        std::cerr << "Creating file " << path << " failed with " << strerror(errno);
        return false;
    }
    close(fd);

    return true;
}

} //namespace anonymous

int main(void)
{
    using namespace SecurityManager;

    if (fileExists(tmp_flag))
        return EXIT_SUCCESS;

    try {
        std::map<std::string, std::vector<std::string>> appPathMap;
        PrivilegeDb::getInstance().GetAllPrivateSharing(appPathMap);
        for (auto &appPaths : appPathMap) {
            try {
                std::string pkgName;
                PrivilegeDb::getInstance().GetAppPkgName(appPaths.first, pkgName);
                for (const auto &path : appPaths.second) {
                    //FIXME Make this service run as slave and master
                    SmackLabels::setupPath(pkgName, path, SECURITY_MANAGER_PATH_RW);
                }
            } catch (const SecurityManager::Exception &e) {
                LogError("Got SecurityManager exception: " << e.GetMessage() << ", ignoring");
            } catch (const std::exception &e) {
                LogError("Got std::exception : " << e.what() << ", ignoring");
            } catch (...) {
                LogError("Got unknown exception, ignoring");
            }
        }
        PrivilegeDb::getInstance().ClearPrivateSharing();
    } catch (const SecurityManager::Exception &e) {
        std::cerr << "Exception throw, msg: " << e.GetMessage() << std::endl;
    } catch (...) {
        std::cerr << "Unknown exception thrown" << std::endl;
    }

    if (!createFile(tmp_flag))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
