/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        sd_journal_provider.h
 * @author      Marcin Lis (m.lis@samsung.com)
 * @version     1.0
 * @brief       This file contains the implementation of systemd journal log provider
 */

#ifndef SECURITYMANAGER_SD_JOURNAL_PROVIDER_H
#define SECURITYMANAGER_SD_JOURNAL_PROVIDER_H

#include <dpl/log/abstract_log_provider.h>
#include <memory>
#include <string>

namespace SecurityManager {
namespace Log {
class SdJournalProvider :
    public AbstractLogProvider
{
  private:
    std::string m_tag;

    static std::string FormatMessage(const char *message,
                                     const char *filename,
                                     int line,
                                     const char *function);

  public:
    SdJournalProvider();
    virtual ~SdJournalProvider();

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

    // All Pedantic logs are translated to Debug
    virtual void Pedantic(const char *message,
                          const char *fileName,
                          int line,
                          const char *function);

    // Set global Tag for all Security Manager Logs
    void SetTag(const char *tag);

}; // class SdJournalProvider

} // namespace Log
} // namespace SecurityManager

#endif // SECURITYMANAGER_SD_JOURNAL_PROVIDER_H
