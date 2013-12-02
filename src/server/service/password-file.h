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
 * @file        password-file.h
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Implementation of PasswordFile, used to manage password files.
 */
#ifndef _PASSWORD_FILE_H_
#define _PASSWORD_FILE_H_

#include <string>
#include <vector>
#include <list>
#include <chrono>

#include <time.h>

#include <dpl/serialization.h>

namespace SecurityServer
{
    class PasswordFile
    {
    public:
        PasswordFile();

        void writeMemoryToFile() const;
        void writeAttemptToFile() const;

        void setPassword(const std::string &password);
        bool checkPassword(const std::string &password) const;
        bool isPasswordActive() const;

        void setHistory(unsigned int history);
        unsigned int getHistorySize() const;

        time_t getExpireTime() const;
        time_t getExpireTimeLeft() const;
        void setExpireTime(int expireTime);

        //attempt manipulating functions
        unsigned int getAttempt() const;
        void resetAttempt();
        void incrementAttempt();
        int getMaxAttempt() const;
        void setMaxAttempt(unsigned int maxAttempt);

        bool isPasswordReused(const std::string &password) const;

        bool checkExpiration() const;
        bool checkIfAttemptsExceeded() const;
        bool isIgnorePeriod() const;

    private:
        typedef std::vector<unsigned char> RawHash;
        typedef std::chrono::duration<double> TimeDiff;
        typedef std::chrono::time_point<std::chrono::monotonic_clock, TimeDiff> TimePoint;

        struct Password: public ISerializable
        {
            Password();
            Password(const RawHash& password);
            Password(IStream& stream);

            virtual void Serialize(IStream &stream) const;

            RawHash m_password;
        };

        typedef std::list<Password> PasswordList;

        void loadMemoryFromFile();

        void resetTimer();
        void preparePwdFile();
        void prepareAttemptFile();
        bool fileExists(const std::string &filename) const;
        bool dirExists(const std::string &dirpath) const;
        static RawHash hashPassword(const std::string &password);

        mutable TimePoint m_retryTimerStart;

        //password file data
        PasswordList m_passwords;
        unsigned int m_maxAttempt;
        unsigned int m_historySize;
        time_t m_expireTime;

        //attempt file data
        unsigned int m_attempt;
    };
}    //namespace SecurityServer

#endif
