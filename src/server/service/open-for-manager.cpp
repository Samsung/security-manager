/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        open-for-manager.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @version     1.0
 * @brief       Implementation of open-for management functions
 */

#include "open-for-manager.h"

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/smack.h>
#include <smack-check.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <security-server.h>
#include <security-server-util.h>

const std::string DATA_DIR = "/var/run/security-server";
const std::string PROHIBITED_STR = "..";
const std::string ALLOWED_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ \
                                   abcdefghijklmnopqrstuvwxyz \
                                   0123456789._-";

namespace SecurityServer
{
    // SockCred implementations
    SockCred::SockCred()
    {
        m_len = sizeof(struct ucred);
        memset(&m_cr, 0, m_len);
    }

    bool SockCred::getCred(int socket)
    {
        if (getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &m_cr, &m_len)) {
            int err = errno;
            LogError("Unable to get client credentials: " << strerror(err));
            return true;
        }

        if (smack_check()) {
            char label[SMACK_LABEL_LEN + 1];
            if (PC_OPERATION_SUCCESS != get_smack_label_from_process(m_cr.pid, label)) {
                LogError("Unable to get smack label of process.");
                return true;
            }
            m_sockSmackLabel = label;
        } else
            m_sockSmackLabel = "";

        return false;
    }

    std::string SockCred::getLabel() const
    {
        return m_sockSmackLabel;
    }

    // SharedFile implementations
    SharedFile::SharedFile()
    {
        if (!dirExist(DATA_DIR.c_str()))
            mkdir(DATA_DIR.c_str(), 0700);
        else {
            deleteDir(DATA_DIR.c_str());
            mkdir(DATA_DIR.c_str(), 0700);
        }
    }

    bool SharedFile::fileExist(const std::string &filename) const
    {
        std::string filepath = DATA_DIR + "/" + filename;
        struct stat buf;

        return ((lstat(filepath.c_str(), &buf) == 0) &&
                (((buf.st_mode) & S_IFMT) != S_IFLNK));
    }

    bool SharedFile::dirExist(const std::string &dirpath) const
    {
        struct stat buf;

        return ((lstat(dirpath.c_str(), &buf) == 0) &&
                (((buf.st_mode) & S_IFMT) == S_IFDIR));
    }

    bool SharedFile::deleteDir(const std::string &dirpath) const
    {
        DIR *dirp;
        struct dirent *dp;
        char path[PATH_MAX];

        if ((dirp = opendir(dirpath.c_str())) == NULL) {
            int err = errno;
            LogError("Cannot open data directory. " << strerror(err));
            return true;
        }

        while ((dp = readdir(dirp)) != NULL) {
            if (strcmp(dp->d_name, ".") && strcmp(dp->d_name, "..")) {
                snprintf(path, (size_t) PATH_MAX, "%s/%s", dirpath.c_str(), dp->d_name);
                if (dp->d_type == DT_DIR) {
                    deleteDir(path);
                } else {
                    unlink(path);
                }
            }
        }
        closedir(dirp);
        rmdir(dirpath.c_str());

        return false;
    }

    bool SharedFile::createFile(const std::string &filename)
    {
        int fd = -1;
        std::string filepath = DATA_DIR + "/" + filename;

        fd = TEMP_FAILURE_RETRY(open(filepath.c_str(), O_CREAT | O_WRONLY | O_EXCL, 0600));
        int err = errno;
        if (-1 == fd) {
            LogError("Cannot create file. Error in open(): " << strerror(err));
            return true;
        }

        TEMP_FAILURE_RETRY(close(fd));

        return false;
    }

    int SharedFile::openFile(const std::string &filename)
    {
        int fd = -1;
        std::string filepath = DATA_DIR + "/" + filename;

        fd = TEMP_FAILURE_RETRY(open(filepath.c_str(), O_CREAT | O_RDWR, 0600));
        int err = errno;
        if (-1 == fd) {
            LogError("Cannot open file. Error in open(): " << strerror(err));
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;
        }

        return fd;
    }

    bool SharedFile::setFileLabel(const std::string &filename, const std::string &label) const
    {
        std::string filepath = DATA_DIR + "/" + filename;

        if (smack_setlabel(filepath.c_str(), label.c_str(), SMACK_LABEL_ACCESS)) {
            LogError("Cannot set SMACK label on file.");
            return true;
        }

        return false;
    }

    bool SharedFile::getFileLabel(const std::string &filename)
    {
        std::string filepath = DATA_DIR + "/" + filename;

        if (smack_check()) {
            char *label = NULL;
            if (PC_OPERATION_SUCCESS != smack_getlabel(filepath.c_str(), &label, SMACK_LABEL_ACCESS)) {
                LogError("Unable to get smack label of process.");
                return true;
            }
            m_fileSmackLabel = label;
            free(label);
        } else
            m_fileSmackLabel.clear();

        return false;
    }

    bool SharedFile::checkFileNameSyntax(const std::string &filename) const
    {
        std::size_t found = filename.find_first_not_of(ALLOWED_CHARS);

        if (found != std::string::npos || '-' == filename[0] ||
            '.' == filename[0]) {
            LogError("Illegal character in filename.");
            return true;
        }

        found = filename.find(PROHIBITED_STR);
        if (found != std::string::npos) {
            LogError("Illegal string in filename.");
            return true;
        }

        return false;
    }

    int SharedFile::getFD(const std::string &filename, int socket, int &fd)
    {
        if (checkFileNameSyntax(filename))
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

        if (m_sockCred.getCred(socket))
            return SECURITY_SERVER_API_ERROR_AUTHENTICATION_FAILED;

        if (!fileExist(filename)) {
            LogSecureDebug("File: " << filename.c_str() << " does not exist.");

            if (createFile(filename))
                return SECURITY_SERVER_API_ERROR_SERVER_ERROR;
        }

        if (getFileLabel(filename))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        if (setFileLabel(filename, m_sockCred.getLabel()))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        fd = openFile(filename);

        if (setFileLabel(filename, m_fileSmackLabel))
            return SECURITY_SERVER_API_ERROR_SERVER_ERROR;

        return SECURITY_SERVER_API_SUCCESS;
    }

} //namespace SecurityServer
