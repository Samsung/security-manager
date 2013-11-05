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
 * @file        audit-smack-log.h
 * @author      Marek Smolinski (m.smolinski@samsung.com)
 * @version     1.0
 * @brief       AuditSmackLog loging SMACK access deny sequentially into files
 */

#ifndef _AUDIT_SMACK_LOG_
#define _AUDIT_SMACK_LOG_

#include <dpl/log/abstract_log_provider.h>

#include <map>
#include <fstream>
#include <mutex>
#include <memory>
#include <functional>

namespace SecurityServer {
namespace Log {

class AuditSmackLog :
    public AbstractLogProvider
{
public:
    AuditSmackLog();
    virtual ~AuditSmackLog();

    bool Fail() const;

    virtual void Debug(const char *message,
                       const char *fileName,
                       int line,
                       const char *function);
    virtual void Info(const char *message,
                      const char *fileName,
                      int line,
                      const char *function);
    virtual void Warning(const char *message,
                         const char *fileName,
                         int line,
                         const char *function);
    virtual void Error(const char *message,
                       const char *fileName,
                       int line,
                       const char *function);
    virtual void Pedantic(const char *message,
                          const char *fileName,
                          int line,
                          const char *function);
    virtual void SecureDebug(const char *message,
                             const char *fileName,
                             int line,
                             const char *function);
    virtual void SecureInfo(const char *message,
                            const char *fileName,
                            int line,
                            const char *function);
    virtual void SecureWarning(const char *message,
                              const char *fileName,
                              int line,
                              const char *function);
    virtual void SecureError(const char *message,
                             const char *fileName,
                             int line,
                             const char *function);

    virtual void SmackAudit(const char *message,
                            const char *fileName,
                            int line,
                            const char *function);

private:
    void HandleWrite(const char *message,
                     const char *fileName,
                     int line,
                     const char *function);

    int CreateLogFile();
    int RemoveOldestLogFile();
    int ParseConfig();
    int ProcessLogDir();
    bool IsFileFull(std::ofstream &fs) const;

    bool m_state;
    unsigned int m_filesCount;
    unsigned int m_fileMaxBytesSize;

    std::map<time_t, std::string> m_fileNameMap;
    std::ofstream m_outputStream;

    std::mutex m_writeMtx;
};

}  // namespace Log
}  // namespace SecurityServer
#endif  // _AUDIT_SMACK_LOG_
