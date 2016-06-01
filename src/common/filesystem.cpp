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
/**
 * @file        filesystem.cpp
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @version     1.0
 * @brief       Wrappers for filesystem operations.
 *
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#include <vector>
#include <memory>
#include <string>

#include <dpl/exception.h>
#include <dpl/errno_string.h>
#include <smack-exceptions.h>

#include <filesystem.h>
#include <filesystem-exception.h>
#include <utils.h>

namespace SecurityManager {
namespace FS {

FileNameVector getDirsFromDirectory(const std::string &path)
{
    return getDirContents(path, S_IFDIR);
}

FileNameVector getFilesFromDirectory(const std::string &path)
{
    return getDirContents(path, S_IFREG);
}

FileNameVector getDirContents(const std::string &path, const mode_t &mode)
{
    FileNameVector result;
    dirent tmp, *ptr;
    int err;
    auto dir = makeUnique(opendir(path.c_str()), closedir);

    if (!dir) {
        err = errno;
        ThrowMsg(FS::Exception::FileError, "Error opening directory: " << GetErrnoString(err));
    }

    while (true) {
        if (readdir_r(dir.get(), &tmp, &ptr)) {
            err = errno;
            ThrowMsg(FS::Exception::FileError, "Error reading directory: " << GetErrnoString(err));
        }

        if (!ptr)
            break;

        struct stat finfo;
        if (0 > fstatat(dirfd(dir.get()), ptr->d_name, &finfo, AT_SYMLINK_NOFOLLOW)) {
            ThrowMsg(FS::Exception::FileError, "Error reading: " << ptr->d_name);
        }

        if ((finfo.st_mode & S_IFMT) == mode)
            result.push_back(ptr->d_name);
    }

    return result;
}

} // namespace FS
} // nanespace SecurityManager

