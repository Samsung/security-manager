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
 * @author      Piotr Bartosiewicz (p.bartosiewi@partner.samsung.com)
 * @version     1.0
 * @brief       Implementation of PasswordFile, used to manage password files.
 */
#include <password-file.h>

#include <fstream>
#include <algorithm>
#include <limits>

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <dpl/log/log.h>

#include <security-server.h>
#include <protocols.h>
#include <password-exception.h>
#include <password-file-buffer.h>

namespace {
    const std::string DATA_DIR = "/opt/data/security-server";
    const std::string PASSWORD_FILE = DATA_DIR + "/password";
    const std::string OLD_VERSION_PASSWORD_FILE = DATA_DIR + "/password.pwd";
    const std::string ATTEMPT_FILE = DATA_DIR + "/attempt";
    const double RETRY_TIMEOUT = 0.5;
    const mode_t FILE_MODE = S_IRUSR | S_IWUSR;
    const unsigned int CURRENT_FILE_VERSION = 3;
} // namespace anonymous

namespace SecurityServer
{
    const time_t PASSWORD_INFINITE_EXPIRATION_TIME = std::numeric_limits<time_t>::max();

    class NoPassword: public IPassword
    {
        public:
            NoPassword(IStream&) {}
            NoPassword() {}

            void Serialize(IStream &stream) const
            {
                Serialization::Serialize(stream, static_cast<unsigned int>(PasswordType::NONE));
            }

            bool match(const std::string &) const
            {
                return false;
            }
    };

    class SHA256Password: public IPassword
    {
        public:
            SHA256Password(IStream& stream)
            {
                Deserialization::Deserialize(stream, m_hash);
            }

            SHA256Password(const std::string &password)
                : m_hash(hash(password)) {}

            SHA256Password(const RawHash& hash)
                : m_hash(hash) {}

            void Serialize(IStream &stream) const
            {
                Serialization::Serialize(stream, static_cast<unsigned int>(PasswordType::SHA256));
                Serialization::Serialize(stream, m_hash);
            }

            bool match(const std::string &password) const
            {
                return m_hash == hash(password);
            }
        private:
            RawHash m_hash;

            static RawHash hash(const std::string &password)
            {
                RawHash result(SHA256_DIGEST_LENGTH);

                SHA256_CTX context;
                SHA256_Init(&context);
                SHA256_Update(&context, reinterpret_cast<const unsigned char*>(password.c_str()),
                        password.size());
                SHA256_Final(result.data(), &context);

                return result;
            }
    };

    // deserialization of new password format
    template <>
    void Deserialization::Deserialize(IStream& stream, IPasswordPtr& ptr)
    {
        unsigned int algorithm;
        Deserialization::Deserialize(stream, algorithm);
        switch (algorithm) {
            case IPassword::PasswordType::NONE:
                ptr.reset(new NoPassword());
                break;
            case IPassword::PasswordType::SHA256:
                ptr.reset(new SHA256Password(stream));
                break;
            default:
                Throw(PasswordException::FStreamReadError);
        }
    }

    PasswordFile::PasswordFile(): m_passwordCurrent(new NoPassword()),
                                  m_maxAttempt(PASSWORD_INFINITE_ATTEMPT_COUNT),
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

    void PasswordFile::resetState()
    {
        m_passwordCurrent.reset(new NoPassword());
        m_maxAttempt = PASSWORD_INFINITE_ATTEMPT_COUNT;
        m_maxHistorySize = 0;
        m_expireTime = PASSWORD_INFINITE_EXPIRATION_TIME;
        m_passwordActive = false;
    }

    void PasswordFile::resetTimer()
    {
        m_retryTimerStart = ClockType::now();
        m_retryTimerStart -= TimeDiff(RETRY_TIMEOUT);
    }

    void PasswordFile::preparePwdFile()
    {
        // check if password file exists
        if (!fileExists(PASSWORD_FILE)) {
            // if old format file exist - load it
            if (tryLoadMemoryFromOldFormatFile()) {
                // save in new format
                writeMemoryToFile();
                // and remove old file
                remove(OLD_VERSION_PASSWORD_FILE.c_str());
                return;
            }

            LogSecureDebug("PWD_DBG not found password file. Creating.");

            //create file
            writeMemoryToFile();
        } else {     //if file exists, load data
            LogSecureDebug("PWD_DBG found password file. Opening.");
            try {
                loadMemoryFromFile();
            } catch (...) {
                LogError("Invalid " << PASSWORD_FILE << " file format");
                resetState();
                writeMemoryToFile();
            }
        }
    }

    void PasswordFile::prepareAttemptFile()
    {
        // check if attempt file exists
        // if not create it
        if (!fileExists(ATTEMPT_FILE)) {
            LogSecureDebug("PWD_DBG not found attempt file. Creating.");

            writeAttemptToFile();
        } else {
            LogSecureDebug("PWD_DBG found attempt file. Opening.");
            std::ifstream attemptFile(ATTEMPT_FILE);
            if(!attemptFile) {
                LogError("Failed to open attempt file.");
                // ignore error
                return;
            }

            attemptFile.read(reinterpret_cast<char*>(&m_attempt), sizeof(unsigned int));
            if(!attemptFile) {
                LogError("Failed to read attempt count.");
                // ignore error
                resetAttempt();
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
        Serialization::Serialize(pwdBuffer, CURRENT_FILE_VERSION);
        Serialization::Serialize(pwdBuffer, m_maxAttempt);
        Serialization::Serialize(pwdBuffer, m_maxHistorySize);
        Serialization::Serialize(pwdBuffer, m_expireTime);
        Serialization::Serialize(pwdBuffer, m_passwordActive);
        Serialization::Serialize(pwdBuffer, m_passwordCurrent);
        Serialization::Serialize(pwdBuffer, m_passwordHistory);

        pwdBuffer.Save(PASSWORD_FILE);

        chmod(PASSWORD_FILE.c_str(), FILE_MODE);
    }

    void PasswordFile::loadMemoryFromFile()
    {
        PasswordFileBuffer pwdFile;

        pwdFile.Load(PASSWORD_FILE);

        unsigned int fileVersion = 0;
        Deserialization::Deserialize(pwdFile, fileVersion);
        if (fileVersion != CURRENT_FILE_VERSION)
            Throw(PasswordException::FStreamReadError);

        m_passwordHistory.clear();

        Deserialization::Deserialize(pwdFile, m_maxAttempt);
        Deserialization::Deserialize(pwdFile, m_maxHistorySize);
        Deserialization::Deserialize(pwdFile, m_expireTime);
        Deserialization::Deserialize(pwdFile, m_passwordActive);
        Deserialization::Deserialize(pwdFile, m_passwordCurrent);
        Deserialization::Deserialize(pwdFile, m_passwordHistory);

        LogSecureDebug("Loaded max_att: " << m_maxAttempt << ", history_size: " <<
                       m_maxHistorySize << ", m_expireTime: " << m_expireTime << ", isActive: " <<
                       m_passwordActive);
    }

    bool PasswordFile::tryLoadMemoryFromOldFormatFile()
    {
        struct stat oldFileStat;
        if (stat(OLD_VERSION_PASSWORD_FILE.c_str(), &oldFileStat) != 0)
            return false;

        static const int ELEMENT_SIZE = sizeof(unsigned) + SHA256_DIGEST_LENGTH;
        static const int VERSION_1_REMAINING = sizeof(unsigned) * 4;
        static const int VERSION_2_REMAINING = VERSION_1_REMAINING + sizeof(bool);
        int remaining = oldFileStat.st_size % ELEMENT_SIZE;

        if (remaining != VERSION_1_REMAINING && remaining != VERSION_2_REMAINING)
            return false;

        try {
            PasswordFileBuffer pwdFile;
            pwdFile.Load(OLD_VERSION_PASSWORD_FILE);

            Deserialization::Deserialize(pwdFile, m_maxAttempt);
            Deserialization::Deserialize(pwdFile, m_maxHistorySize);
            Deserialization::Deserialize(pwdFile, m_expireTime);
            if (m_expireTime == 0)
                m_expireTime = PASSWORD_INFINITE_EXPIRATION_TIME;
            if (remaining == VERSION_2_REMAINING)
                Deserialization::Deserialize(pwdFile, m_passwordActive);
            else
                m_passwordActive = true;

            // deserialize passwords in old format
            struct OldPassword {
                OldPassword() {}
                OldPassword(IStream &stream)
                {
                    Deserialization::Deserialize(stream, m_hash);
                }
                IPassword::RawHash m_hash;
            };
            std::list<OldPassword> oldFormatPasswords;
            Deserialization::Deserialize(pwdFile, oldFormatPasswords);

            // convert passwords to new format
            m_passwordHistory.clear();
            if (oldFormatPasswords.empty()) {
                m_passwordCurrent.reset(new NoPassword());
                m_passwordActive = false;
            } else {
                m_passwordCurrent.reset(new SHA256Password(oldFormatPasswords.front().m_hash));
                std::for_each(++oldFormatPasswords.begin(), oldFormatPasswords.end(),
                        [&] (const OldPassword& pwd)
                        {m_passwordHistory.push_back(IPasswordPtr(new SHA256Password(pwd.m_hash)));}
                        );
            }
        } catch (...) {
            LogWarning("Invalid " << OLD_VERSION_PASSWORD_FILE << " file format");
            resetState();
            return false;
        }

        return true;
    }

    void PasswordFile::writeAttemptToFile() const
    {
        std::ofstream attemptFile(ATTEMPT_FILE, std::ofstream::trunc);

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
        if (0 <= (fd = open(ATTEMPT_FILE.c_str(), O_WRONLY | O_APPEND))) {
            fchmod(fd, FILE_MODE);
            fsync(fd); // force synchronization system buffers with file
            close(fd);
        } else {
            int err = errno;
            LogError("Failed to sync attempt file: " << ATTEMPT_FILE << "strerror: " << strerror(err));
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

        while(m_passwordHistory.size() > history)
            m_passwordHistory.pop_back();
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
        LogSecureDebug("Checking if pwd is reused. HistorySize: " << m_passwordHistory.size() <<
                       ", MaxHistorySize: " << getMaxHistorySize());

        //go through history and check if password existed earlier
        if(std::any_of(m_passwordHistory.begin(), m_passwordHistory.end(),
                       [&password](const IPasswordPtr& pwd) { return pwd->match(password); })) {
            LogSecureDebug("Passwords match!");
            return true;
        }

        LogSecureDebug("isPasswordReused: No passwords match, password not reused.");
        return false;
    }

    void PasswordFile::setPassword(const std::string &password)
    {
        //put current password to history
        m_passwordHistory.push_front(std::move(m_passwordCurrent));

        //erase last password if we exceed max history size
        if(m_passwordHistory.size() > getMaxHistorySize())
            m_passwordHistory.pop_back();

        //replace current password with new one
        m_passwordCurrent.reset(new SHA256Password(password));
    }

    bool PasswordFile::checkPassword(const std::string &password) const
    {
        return m_passwordCurrent->match(password);
    }

    void PasswordFile::setExpireTime(time_t expireTime)
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
        TimePoint retryTimerStop = ClockType::now();
        TimeDiff diff = retryTimerStop - m_retryTimerStart;

        m_retryTimerStart = retryTimerStop;

        return (diff.count() < RETRY_TIMEOUT);
    }

    bool PasswordFile::isHistoryActive() const
    {
        return (m_maxHistorySize != 0);
    }
} //namespace SecurityServer

