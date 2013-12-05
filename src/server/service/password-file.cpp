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
 * @file        password-file.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Implementation of PasswordFile, used to manage password files.
 */
#include <password-file.h>

#include <fstream>
#include <algorithm>

#include <openssl/sha.h>

#include <sys/stat.h>

#include <dpl/log/log.h>

#include <security-server.h>
#include <protocols.h>
#include <password-exception.h>
#include <password-file-buffer.h>

#include <fcntl.h>
#include <string.h>

const std::string DATA_DIR = "/opt/data/security-server";
const std::string PASSWORD_FILE = "password.pwd";
const std::string ATTEMPT_FILE = "attempt";
const double RETRY_TIMEOUT = 0.5;

namespace SecurityServer
{
    PasswordFile::Password::Password()
    {
        m_password = PasswordFile::hashPassword("");
    }

    PasswordFile::Password::Password(const RawHash& password)
    {
        m_password = password;
    }

    PasswordFile::Password::Password(IStream& stream)
    {
        Deserialization::Deserialize(stream, m_password);
    }

    void PasswordFile::Password::Serialize(IStream &stream) const
    {
        Serialization::Serialize(stream, m_password);
    }

    PasswordFile::PasswordFile(): m_maxAttempt(PASSWORD_INFINITE_ATTEMPT_COUNT),
                                  m_maxHistorySize(0),
                                  m_expireTime(PASSWORD_INFINITE_EXPIRATION_TIME),
                                  m_passwordActive(false), m_attempt(0)
    {
        // check if data directory exists
        // if not create it
        if (!dirExists(DATA_DIR.c_str())) {
            if(mkdir(DATA_DIR.c_str(), 0700)) {
                LogError("Failed to create directory for files. Error: " << strerror(errno));
                Throw(PasswordException::MakeDirError);
            }
        }

        preparePwdFile();
        prepareAttemptFile();
        resetTimer();
    }

    void PasswordFile::resetTimer()
    {
        m_retryTimerStart = std::chrono::monotonic_clock::now();
        m_retryTimerStart -= TimeDiff(RETRY_TIMEOUT);
    }

    void PasswordFile::preparePwdFile()
    {
        std::string s_pwdfilePath = DATA_DIR + "/" + PASSWORD_FILE;

        // check if password file exists
        // if not create it
        if (!fileExists(s_pwdfilePath)) {
            LogSecureDebug("PWD_DBG not found password file. Creating.");
            __mode_t oldMask = umask(S_IRUSR | S_IWUSR);

            //create file
            writeMemoryToFile();

            umask(oldMask);
        } else {     //if file exists, load data
            LogSecureDebug("PWD_DBG found password file. Opening.");
            loadMemoryFromFile();
        }
    }

    void PasswordFile::prepareAttemptFile()
    {
        std::string s_attemptfilePath = DATA_DIR + "/" + ATTEMPT_FILE;

        // check if attempt file exists
        // if not create it
        if (!fileExists(s_attemptfilePath)) {
            LogSecureDebug("PWD_DBG not found attempt file. Creating.");
            __mode_t oldMask = umask(S_IRUSR | S_IWUSR);

            writeAttemptToFile();

            umask(oldMask);
        } else {
            LogSecureDebug("PWD_DBG found attempt file. Opening.");
            std::ifstream attemptFile(s_attemptfilePath);
            if(!attemptFile.good()) {
                LogError("Failed to open attempt file.");
                Throw(PasswordException::FStreamOpenError);
            }

            attemptFile.read(reinterpret_cast<char*>(&m_attempt), sizeof(unsigned int));
            if(!attemptFile) {
                LogError("Failed to read attempt count.");
                Throw(PasswordException::FStreamReadError);
            }
        }
    }

    bool PasswordFile::fileExists(const std::string &filename) const
    {
        struct stat buf;

        return ((stat(filename.c_str(), &buf) == 0));
    }

    bool PasswordFile::dirExists(const std::string &dirpath) const
    {
        struct stat buf;

        return ((stat(dirpath.c_str(), &buf) == 0) && (((buf.st_mode) & S_IFMT) == S_IFDIR));
    }

    void PasswordFile::writeMemoryToFile() const
    {
        PasswordFileBuffer pwdBuffer;

        LogSecureDebug("Saving max_att: " << m_maxAttempt << ", history_size: " <<
                       m_maxHistorySize << ", m_expireTime: " << m_expireTime << ", isActive: " <<
                       m_passwordActive);

        //serialize password attributes
        Serialization::Serialize(pwdBuffer, m_maxAttempt);
        Serialization::Serialize(pwdBuffer, m_maxHistorySize);
        Serialization::Serialize(pwdBuffer, m_expireTime);
        Serialization::Serialize(pwdBuffer, m_passwordActive);
        Serialization::Serialize(pwdBuffer, m_passwords);

        pwdBuffer.Save(DATA_DIR + "/" + PASSWORD_FILE);
    }

    void PasswordFile::loadMemoryFromFile()
    {
        PasswordFileBuffer pwdFile;

        pwdFile.Load(DATA_DIR + "/" + PASSWORD_FILE);

        m_passwords.clear();

        Deserialization::Deserialize(pwdFile, m_maxAttempt);
        Deserialization::Deserialize(pwdFile, m_maxHistorySize);
        Deserialization::Deserialize(pwdFile, m_expireTime);
        Deserialization::Deserialize(pwdFile, m_passwordActive);
        Deserialization::Deserialize(pwdFile, m_passwords);

        LogSecureDebug("Loaded max_att: " << m_maxAttempt << ", history_size: " <<
                       m_maxHistorySize << ", m_expireTime: " << m_expireTime << ", isActive: " <<
                       m_passwordActive);
    }

    void PasswordFile::writeAttemptToFile() const
    {
        std::ofstream attemptFile(DATA_DIR + "/" + ATTEMPT_FILE, std::ofstream::trunc);

        if(!attemptFile.good()) {
            LogError("Failed to open attempt file.");
            Throw(PasswordException::FStreamOpenError);
        }

        attemptFile.write(reinterpret_cast<const char*>(&m_attempt), sizeof(unsigned int));
        if(!attemptFile) {
            LogError("Failed to write attempt count.");
            Throw(PasswordException::FStreamWriteError);
        }
        attemptFile.close();

        int fd;
        if (0 <= (fd = open((DATA_DIR + "/" + ATTEMPT_FILE).c_str(), O_WRONLY | O_APPEND))) {
            fsync(fd); // force synchronization system buffers with file
            close(fd);
        } else {
            int err = errno;
            LogError("Failed to sync attempt file: " << DATA_DIR << "/" << ATTEMPT_FILE << "strerror: " << strerror(err));
        }
    }

    void PasswordFile::activatePassword()
    {
        m_passwordActive = true;
    }

    bool PasswordFile::isPasswordActive() const
    {
        return m_passwordActive;
    }

    void PasswordFile::setMaxHistorySize(unsigned int history)
    {
        //setting history should be independent from password being set
        m_maxHistorySize = history;

        //we want to keep 1 current pwd, plus history amount of passwords.
        if(m_passwords.size() > 1+history)
            m_passwords.resize(1+history);
    }

    unsigned int PasswordFile::getMaxHistorySize() const
    {
        return m_maxHistorySize;
    }

    unsigned int PasswordFile::getAttempt() const
    {
        return m_attempt;
    }

    void PasswordFile::resetAttempt()
    {
        m_attempt = 0;
    }

    void PasswordFile::incrementAttempt()
    {
        m_attempt++;
    }

    int PasswordFile::getMaxAttempt() const
    {
        return m_maxAttempt;
    }

    void PasswordFile::setMaxAttempt(unsigned int maxAttempt)
    {
        m_maxAttempt = maxAttempt;
    }

    bool PasswordFile::isPasswordReused(const std::string &password) const
    {
        RawHash hashedPwd = hashPassword(password);

        LogSecureDebug("Checking if pwd is reused. PwdCount: " << m_passwords.size() <<
                       ", PwdMaxHistory: " << getMaxHistorySize());

        auto history_beginning = (m_passwords.begin())++;

        if(std::find_if(history_beginning, m_passwords.end(),
                        [&hashedPwd](const Password& pwd) { return (pwd.m_password == hashedPwd); })
                != m_passwords.end()) {
            LogSecureDebug("Passwords match!");
            return true;
        }

        LogSecureDebug("isPasswordReused: No passwords match, password not reused.");
        return false;
    }

    void PasswordFile::setPassword(const std::string &password)
    {
        RawHash hashedPwd = hashPassword(password);

        m_passwords.push_front(Password(hashedPwd));

        //one current password, plus history amount of passwords
        if(m_passwords.size() > 1+getMaxHistorySize())
            m_passwords.pop_back();
    }

    bool PasswordFile::checkPassword(const std::string &password) const
    {
        RawHash hashedPwd = hashPassword(password);

        return (hashedPwd == m_passwords.begin()->m_password);
    }

    void PasswordFile::setExpireTime(int expireTime)
    {
        if(isPasswordActive())
            m_expireTime = expireTime;
        else {
            LogError("Can't set expiration time, password not active.");
            Throw(PasswordException::PasswordNotActive);
        }
    }

    unsigned int PasswordFile::getExpireTimeLeft() const
    {
        if(m_expireTime != PASSWORD_INFINITE_EXPIRATION_TIME) {
            time_t timeLeft = m_expireTime - time(NULL);
            return (timeLeft < 0) ? 0 : static_cast<unsigned int>(timeLeft);
        } else
            return PASSWORD_API_NO_EXPIRATION;
    }

    bool PasswordFile::checkExpiration() const
    {
        //return true if expired, else false
        return ((m_expireTime != PASSWORD_INFINITE_EXPIRATION_TIME) && (time(NULL) > m_expireTime));
    }

    bool PasswordFile::checkIfAttemptsExceeded() const
    {
        return ((m_maxAttempt != PASSWORD_INFINITE_ATTEMPT_COUNT) && (m_attempt > m_maxAttempt));
    }

    bool PasswordFile::isIgnorePeriod() const
    {
        TimePoint retryTimerStop = std::chrono::monotonic_clock::now();
        TimeDiff diff = retryTimerStop - m_retryTimerStart;

        m_retryTimerStart = retryTimerStop;

        return (diff.count() < RETRY_TIMEOUT);
    }

    bool PasswordFile::isHistoryActive() const
    {
        return (m_maxHistorySize != 0);
    }

    //hashPassword is also used in Password struct constructor, that's why it's static. Moreover
    //it is assumed that incorrect input password was checked earlier.
    PasswordFile::RawHash PasswordFile::hashPassword(const std::string &password)
    {
        RawHash result(SHA256_DIGEST_LENGTH);

        SHA256_CTX context;
        SHA256_Init(&context);
        SHA256_Update(&context, reinterpret_cast<const unsigned char*>(password.c_str()),
                      password.size());
        SHA256_Final(result.data(), &context);

        return result;
    }
} //namespace SecurityServer

