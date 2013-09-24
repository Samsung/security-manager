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
 * @file        client-password.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of password functions.
 */

#include <cstring>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>

#include <security-server.h>

inline bool isPasswordIncorrect(const char* pwd)
{
    return (pwd == NULL || strlen(pwd) == 0 || strlen(pwd) > SecurityServer::MAX_PASSWORD_LEN);
}

SECURITY_SERVER_API
int security_server_is_pwd_valid(unsigned int *current_attempts,
                                 unsigned int *max_attempts,
                                 unsigned int *valid_secs)
{
    using namespace SecurityServer;

    try {
        if (NULL == current_attempts || NULL == max_attempts ||
            NULL == valid_secs) {

            LogError("Wrong input param");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        MessageBuffer send, recv;

        *current_attempts = 0;
        *max_attempts = 0;
        *valid_secs = 0;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_IS_PWD_VALID));

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_CHECK, send.Pop(), recv);
        if (SECURITY_SERVER_API_SUCCESS != retCode) {
            LogDebug("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        if(retCode == SECURITY_SERVER_API_ERROR_PASSWORD_EXIST) {
            Deserialization::Deserialize(recv, *current_attempts);
            Deserialization::Deserialize(recv, *max_attempts);
            Deserialization::Deserialize(recv, *valid_secs);
        }

        return retCode;
    } catch (MessageBuffer::Exception::Base &e) {
        LogError("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

SECURITY_SERVER_API
int security_server_chk_pwd(const char *challenge,
                            unsigned int *current_attempts,
                            unsigned int *max_attempts,
                            unsigned int *valid_secs)
{
    using namespace SecurityServer;

    try {
        if (current_attempts == NULL || max_attempts == NULL || valid_secs == NULL ||
            isPasswordIncorrect(challenge)) {
            LogError("Wrong input param");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        MessageBuffer send, recv;

        *current_attempts = 0;
        *max_attempts = 0;
        *valid_secs = 0;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_CHK_PWD));
        Serialization::Serialize(send, std::string(challenge));

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_CHECK, send.Pop(), recv);
        if (SECURITY_SERVER_API_SUCCESS != retCode) {
            LogDebug("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        switch (retCode) {
        case SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH:
        case SECURITY_SERVER_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED:
        case SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED:
        case SECURITY_SERVER_API_SUCCESS:
            Deserialization::Deserialize(recv, *current_attempts);
            Deserialization::Deserialize(recv, *max_attempts);
            Deserialization::Deserialize(recv, *valid_secs);
            break;
        default:
            break;
        }

        return retCode;
    } catch (MessageBuffer::Exception::Base &e) {
        LogError("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

SECURITY_SERVER_API
int security_server_set_pwd(const char *cur_pwd,
                            const char *new_pwd,
                            const unsigned int max_challenge,
                            const unsigned int valid_period_in_days)
{
    using namespace SecurityServer;

    try {
        if (NULL == cur_pwd)
            cur_pwd = "";

        if (isPasswordIncorrect(new_pwd) || strlen(cur_pwd) > MAX_PASSWORD_LEN) {
            LogError("Wrong input param.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        MessageBuffer send, recv;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_SET_PWD));
        Serialization::Serialize(send, std::string(cur_pwd));
        Serialization::Serialize(send, std::string(new_pwd));
        Serialization::Serialize(send, max_challenge);
        Serialization::Serialize(send, valid_period_in_days);

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_SET, send.Pop(), recv);
        if (SECURITY_SERVER_API_SUCCESS != retCode) {
            LogError("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        return retCode;
    } catch (MessageBuffer::Exception::Base &e) {
        LogError("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

SECURITY_SERVER_API
int security_server_set_pwd_validity(const unsigned int valid_period_in_days)
{
    using namespace SecurityServer;

    try {
        MessageBuffer send, recv;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_SET_PWD_VALIDITY));
        Serialization::Serialize(send, valid_period_in_days);

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_SET, send.Pop(), recv);
        if (SECURITY_SERVER_API_SUCCESS != retCode) {
            LogError("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        return retCode;
    } catch (MessageBuffer::Exception::Base &e) {
        LogError("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

SECURITY_SERVER_API
int security_server_set_pwd_max_challenge(const unsigned int max_challenge)
{
    using namespace SecurityServer;

    try {
        MessageBuffer send, recv;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_SET_PWD_MAX_CHALLENGE));
        Serialization::Serialize(send, max_challenge);

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_SET, send.Pop(), recv);
        if (SECURITY_SERVER_API_SUCCESS != retCode) {
            LogError("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        return retCode;
    } catch (MessageBuffer::Exception::Base &e) {
        LogError("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

SECURITY_SERVER_API
int security_server_reset_pwd(const char *new_pwd,
                              const unsigned int max_challenge,
                              const unsigned int valid_period_in_days)
{
    using namespace SecurityServer;

    try {
        if (isPasswordIncorrect(new_pwd)) {
            LogError("Wrong input param.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        MessageBuffer send, recv;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_RST_PWD));
        Serialization::Serialize(send, std::string(new_pwd));
        Serialization::Serialize(send, max_challenge);
        Serialization::Serialize(send, valid_period_in_days);

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_SET, send.Pop(), recv);
        if (SECURITY_SERVER_API_SUCCESS != retCode) {
            LogError("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        return retCode;
    } catch (MessageBuffer::Exception::Base &e) {
        LogError("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

SECURITY_SERVER_API
int security_server_set_pwd_history(int history_size)
{
    using namespace SecurityServer;

    try {
        if (history_size > static_cast<int>(MAX_PASSWORD_HISTORY) || history_size < 0) {
            LogError("Wrong input param.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        MessageBuffer send, recv;

        Serialization::Serialize(send, static_cast<int>(PasswordHdrs::HDR_SET_PWD_HISTORY));
        Serialization::Serialize(send, static_cast<unsigned int>(history_size));

        int retCode = sendToServer(SERVICE_SOCKET_PASSWD_SET, send.Pop(), recv);
        if (SECURITY_SERVER_API_SUCCESS != retCode) {
            LogError("Error in sendToServer. Error code: " << retCode);
            return retCode;
        }

        Deserialization::Deserialize(recv, retCode);

        return retCode;
    } catch (MessageBuffer::Exception::Base &e) {
        LogError("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}
