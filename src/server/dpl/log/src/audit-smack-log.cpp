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
 * @file        audit-smack-log.cpp
 * @author      Marek Smolinski (m.smolinski@samsung.com)
 * @version     1.0
 * @brief       AuditSmackLog loging SMACK access deny sequentially into files
 */

#include <iostream>
#include <fstream>
#include <map>
#include <cstring>
#include <mutex>

#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <cassert>

#include <sys/smack.h>
#include <sys/stat.h>

#include <dpl/log/audit-smack-log.h>
#include <dpl/log/log.h>

#define UNUSED __attribute__((unused))

namespace {

const std::string AUDIT_CONFIG_LOG_PATH = "/etc/security/";
const std::string AUDIT_CONFIG_FILENAME = "security-server-audit.conf";
const std::string AUDIT_LOG_DIRECTORY = "/var/log/audit/";
const std::string AUDIT_LOG_FILENAME_PREFIX = "audit-smack";
const std::string AUDIT_LOG_SMACK_LABEL = "security-server::audit-files";

} // namespace anonymous

namespace SecurityServer {
namespace Log {

AuditSmackLog::AuditSmackLog()
    : m_state(true), m_filesCount(0), m_fileMaxBytesSize(0)
{
    if (ParseConfig() != 0) {
        goto error;
    }

    if (ProcessLogDir() != 0) {
        goto error;
    }

    if (m_state) {

        // reduce existing files count in log dir if config file was changed
        while (m_fileNameMap.size() > m_filesCount) {
            if (RemoveOldestLogFile() != 0) {
                goto error;
            }
        }

        if (m_fileNameMap.size() == 0) {
            if (CreateLogFile() != 0) {
                goto error;
            }
        } else {
            std::string filename(AUDIT_LOG_DIRECTORY);
            filename += m_fileNameMap.rbegin()->second;
            m_outputStream.open(filename, std::ios_base::app);
        }
    }

    return;

error:
    m_state = false;

}

AuditSmackLog::~AuditSmackLog(){}

bool AuditSmackLog::Fail() const
{
    return !m_state;
}

void AuditSmackLog::SmackAudit(const char *message,
                               const char *fileName,
                               int line,
                               const char *function)
{
    if (m_state) {
        HandleWrite(message, fileName, line, function);
    }
}

void AuditSmackLog::HandleWrite(const char *message,
                                const char *filename,
                                int line,
                                const char *function)
{
    std::lock_guard<std::mutex> lock(m_writeMtx);
    if (IsFileFull(m_outputStream)) {
        if (CreateLogFile() != 0) {
            m_state = false;
            return;
        }

        if (m_fileNameMap.size() > m_filesCount) {
            if (RemoveOldestLogFile() != 0) {
                m_state = false;
                return;
            }
        }
    }

    m_outputStream << std::string("[") <<
        LocateSourceFileName(filename) << std::string(":") << line <<
        std::string("] ") << function << std::string("(): ") << message << '\n';
}

int AuditSmackLog::CreateLogFile()
{
    time_t sec = time(NULL);
    std::string fname(AUDIT_LOG_FILENAME_PREFIX);
    std::string pathname(AUDIT_LOG_DIRECTORY);

    fname += std::to_string(sec);
    fname += ".log";
    pathname += fname;

    if (m_outputStream.is_open())
        m_outputStream.close();

    m_outputStream.open(pathname.c_str());

    if (!m_outputStream) {
        return -1;
    }

    if (smack_setlabel(pathname.c_str(),
                       AUDIT_LOG_SMACK_LABEL.c_str(),
                       SMACK_LABEL_ACCESS) != 0)  {
        return -1;
    }

    m_fileNameMap.insert(std::make_pair(sec, fname));
    return 0;
}

int AuditSmackLog::RemoveOldestLogFile()
{
    assert(m_fileNameMap.size() > 0);

    auto it = m_fileNameMap.begin();
    std::string filename(AUDIT_LOG_DIRECTORY);
    filename += it->second;

    if (unlink(filename.c_str()) == 0) {
        m_fileNameMap.erase(it);
        return 0;
    }

    return -1;
}

int AuditSmackLog::ParseConfig()
{
    struct stat sb;
    if (stat(AUDIT_CONFIG_LOG_PATH.c_str(), &sb) != 0) {
        return -1;
    }

    std::ifstream in(AUDIT_CONFIG_LOG_PATH + AUDIT_CONFIG_FILENAME,
                     std::ios_base::in);
    if (!in) {
        return -1;
    }

    in >> m_filesCount >> m_fileMaxBytesSize;

    if (in.fail()) {
        return -1;
    }

    return (m_filesCount > 0 && m_fileMaxBytesSize > 0) ? 0 : -1;
}

int AuditSmackLog::ProcessLogDir()
{
    DIR *dir;
    dirent *dp;

    if ((dir = opendir(AUDIT_LOG_DIRECTORY.c_str())) == NULL) {
        return -1;
    }

    while ((dp = readdir(dir)) != NULL) {
        if (AUDIT_LOG_FILENAME_PREFIX.compare(0, std::string::npos,
                                      dp->d_name,
                                      AUDIT_LOG_FILENAME_PREFIX.size()) == 0) {
            errno = 0;
            char *pEnd;
            time_t fUnxTime = static_cast<time_t>(
                    strtoull(dp->d_name + AUDIT_LOG_FILENAME_PREFIX.size(),
                             &pEnd, 10));

            if (errno != 0) {
                closedir(dir);
                return -1;
            }

            m_fileNameMap.insert(
                    std::make_pair(fUnxTime, std::string(dp->d_name)));
        }
    }

    closedir(dir);

    return 0;
}

bool AuditSmackLog::IsFileFull(std::ofstream &fs) const
{
    return fs.tellp() > m_fileMaxBytesSize;
}

void AuditSmackLog::Debug(const char *message UNUSED,
                          const char *filename UNUSED,
                          int line UNUSED,
                          const char *function UNUSED)
{
}

void AuditSmackLog::Info(const char *message UNUSED,
                         const char *filename UNUSED,
                         int line UNUSED,
                         const char *function UNUSED)
{
}

void AuditSmackLog::Warning(const char *message UNUSED,
                            const char *filename UNUSED,
                            int line UNUSED,
                            const char *function UNUSED)
{
}

void AuditSmackLog::Error(const char *message UNUSED,
                          const char *filename UNUSED,
                          int line UNUSED,
                          const char *function UNUSED)
{
}

void AuditSmackLog::Pedantic(const char *message UNUSED,
                             const char *filename UNUSED,
                             int line UNUSED,
                             const char *function UNUSED)
{
}

void AuditSmackLog::SecureDebug(const char *message UNUSED,
                                const char *filename UNUSED,
                                int line UNUSED,
                                const char *function UNUSED)
{
}

void AuditSmackLog::SecureInfo(const char *message UNUSED,
                               const char *filename  UNUSED,
                               int line  UNUSED,
                               const char *function UNUSED)
{
}

void AuditSmackLog::SecureWarning(const char *message UNUSED,
                                  const char *filename UNUSED,
                                  int line UNUSED,
                                  const char *function UNUSED)
{
}

void AuditSmackLog::SecureError(const char *message UNUSED,
                                const char *filename UNUSED,
                                int line UNUSED,
                                const char *function UNUSED)
{
}

} // namespace Log
} // namespace SecurityServer
