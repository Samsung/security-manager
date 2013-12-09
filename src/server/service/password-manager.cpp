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
 * @file        password-manager.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Implementation of password management functions
 */

#include <password-manager.h>

#include <iostream>
#include <iterator>
#include <algorithm>

#include <limits.h>

#include <dpl/log/log.h>

#include <protocols.h>

#include <security-server.h>

namespace {
    bool calculateExpiredTime(unsigned int receivedDays, unsigned int &validSecs)
    {
        validSecs = SecurityServer::PASSWORD_INFINITE_EXPIRATION_TIME;

        //when receivedDays means infinite expiration, return default validSecs value.
        if(receivedDays == SecurityServer::PASSWORD_INFINITE_EXPIRATION_DAYS)
            return true;

        time_t curTime = time(NULL);

        if (receivedDays > ((UINT_MAX - curTime) / 86400)) {
            LogError("Incorrect input param.");
            return false;
        } else {
            validSecs = (curTime + (receivedDays * 86400));
            return true;
        }
    }
} //namespace

namespace SecurityServer
{
    int PasswordManager::isPwdValid(unsigned int &currentAttempt, unsigned int &maxAttempt,
                                    unsigned int &expirationTime) const
    {
        if (!m_pwdFile.isPasswordActive()) {
            LogError("Current password not active.");
            return SECURITY_SERVER_API_ERROR_NO_PASSWORD;
        } else {
            currentAttempt = m_pwdFile.getAttempt();
            maxAttempt = m_pwdFile.getMaxAttempt();
            expirationTime = m_pwdFile.getExpireTimeLeft();

            return SECURITY_SERVER_API_ERROR_PASSWORD_EXIST;
        }

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::checkPassword(const std::string &challenge, unsigned int &currentAttempt,
                                       unsigned int &maxAttempt, unsigned int &expirationTime)
    {
        LogSecureDebug("Inside checkPassword function.");

        if (m_pwdFile.isIgnorePeriod()) {
            LogError("Retry timeout occurred.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_RETRY_TIMER;
        }

        if (!m_pwdFile.isPasswordActive()) {
            LogError("Password not active.");
            return SECURITY_SERVER_API_ERROR_NO_PASSWORD;
        }

        m_pwdFile.incrementAttempt();
        m_pwdFile.writeAttemptToFile();

        currentAttempt = m_pwdFile.getAttempt();
        maxAttempt = m_pwdFile.getMaxAttempt();
        expirationTime = m_pwdFile.getExpireTimeLeft();

        if (m_pwdFile.checkIfAttemptsExceeded()) {
            LogError("Too many tries.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED;
        }

        if (!m_pwdFile.checkPassword(challenge)) {
            LogError("Wrong password.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH;
        }

        if (m_pwdFile.checkExpiration()) {
            LogError("Password expired.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED;
        }

        m_pwdFile.resetAttempt();
        m_pwdFile.writeAttemptToFile();

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::setPassword(const std::string &currentPassword,
                                     const std::string &newPassword,
                                     const unsigned int receivedAttempts,
                                     const unsigned int receivedDays)
    {
        LogSecureDebug("Curpwd = " << currentPassword << ", newpwd = " << newPassword <<
                       ", recatt = " << receivedAttempts << ", recdays = " << receivedDays);

        unsigned int valid_secs = 0;

        if (m_pwdFile.isIgnorePeriod()) {
            LogError("Retry timeout occured.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_RETRY_TIMER;
        }

        //check if passwords are correct
        if (currentPassword.size() > MAX_PASSWORD_LEN) {
            LogError("Current password length failed.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (newPassword.size() > MAX_PASSWORD_LEN) {
            LogError("New password length failed.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        //check delivered currentPassword
        //when m_passwordActive flag is true, currentPassword shouldn't be empty
        if (currentPassword.empty() && m_pwdFile.isPasswordActive()) {
            LogError("Password is already set. Max history: " << m_pwdFile.getMaxHistorySize());
            return SECURITY_SERVER_API_ERROR_PASSWORD_EXIST;
        }

        //increment attempt count before checking it against max attempt count
        m_pwdFile.incrementAttempt();
        m_pwdFile.writeAttemptToFile();

        // check attempt
        if (m_pwdFile.checkIfAttemptsExceeded()) {
            LogError("Too many attempts.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED;
        }

        //check current password, however only when we don't send empty string as current.
        if(!currentPassword.empty()) {
            if(!m_pwdFile.checkPassword(currentPassword)) {
                LogError("Wrong password.");
                return SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH;
            }
        }

        //check if password expired
        if (m_pwdFile.checkExpiration()) {
            LogError("Password expired.");
            return SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED;
        }

        //check history, however only if history is active
        if (m_pwdFile.isPasswordActive() && m_pwdFile.isHistoryActive()) {
            if (m_pwdFile.isPasswordReused(newPassword)) {
                LogError("Password reused.");
                return SECURITY_SERVER_API_ERROR_PASSWORD_REUSED;
            }
        }

        if(!calculateExpiredTime(receivedDays, valid_secs)) {
            LogError("Received expiration time incorrect.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        //setting password
        m_pwdFile.setPassword(newPassword);
        m_pwdFile.activatePassword();
        m_pwdFile.setMaxAttempt(receivedAttempts);
        m_pwdFile.setExpireTime(valid_secs);
        m_pwdFile.writeMemoryToFile();

        m_pwdFile.resetAttempt();
        m_pwdFile.writeAttemptToFile();

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::setPasswordValidity(const unsigned int receivedDays)
    {
        unsigned int valid_secs = 0;

        LogSecureDebug("received_days: " << receivedDays);

        if (!m_pwdFile.isPasswordActive()) {
            LogError("Current password is not active.");
            return SECURITY_SERVER_API_ERROR_NO_PASSWORD;
        }

        if(!calculateExpiredTime(receivedDays, valid_secs))
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

        m_pwdFile.setExpireTime(valid_secs);
        m_pwdFile.writeMemoryToFile();

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::resetPassword(const std::string &newPassword,
                                       const unsigned int receivedAttempts,
                                       const unsigned int receivedDays)
    {
        unsigned int valid_secs = 0;

        if(!calculateExpiredTime(receivedDays, valid_secs))
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

        m_pwdFile.setPassword(newPassword);
        m_pwdFile.activatePassword();
        m_pwdFile.setMaxAttempt(receivedAttempts);
        m_pwdFile.setExpireTime(valid_secs);
        m_pwdFile.writeMemoryToFile();

        m_pwdFile.resetAttempt();
        m_pwdFile.writeAttemptToFile();

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::setPasswordHistory(const unsigned int history)
    {
        if(history > MAX_PASSWORD_HISTORY) {
            LogError("Incorrect input param.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        m_pwdFile.setMaxHistorySize(history);
        m_pwdFile.writeMemoryToFile();

        return SECURITY_SERVER_API_SUCCESS;
    }

    int PasswordManager::setPasswordMaxChallenge(const unsigned int maxChallenge)
    {
        // check if there is password
        if (!m_pwdFile.isPasswordActive()) {
            LogError("Password not active.");
            return SECURITY_SERVER_API_ERROR_NO_PASSWORD;
        }

        m_pwdFile.setMaxAttempt(maxChallenge);
        m_pwdFile.writeMemoryToFile();

        m_pwdFile.resetAttempt();
        m_pwdFile.writeAttemptToFile();

        return SECURITY_SERVER_API_SUCCESS;
    }
} //namespace SecurityServer
