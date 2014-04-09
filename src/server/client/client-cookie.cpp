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
 * @file        client-cookie.cpp
 * @author      Pawel Polawski (p.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This file contain implementation of cookie functions for getting cookies
 */


#include <cstdio>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>

#include <security-server.h>

SECURITY_SERVER_API
int security_server_get_cookie_size(void)
{
    return SecurityServer::COOKIE_SIZE;
}

SECURITY_SERVER_API
int security_server_request_cookie(char *cookie, size_t bufferSize)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;
    std::vector<char> receivedCookie;

    LogDebug("security_server_request_cookie() called");

    return try_catch([&] {
        //checking parameters
        if (bufferSize < COOKIE_SIZE) {
            LogDebug("Buffer for cookie too small");
            return SECURITY_SERVER_API_ERROR_BUFFER_TOO_SMALL;
        }
        if (cookie == NULL) {
            LogDebug("Cookie pointer empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        //put data into buffer
        Serialization::Serialize(send, (int)CookieCall::GET_COOKIE);

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET_COOKIE_GET, send.Pop(), recv);
        if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_SERVER_API_SUCCESS)
            return retval;

        Deserialization::Deserialize(recv, receivedCookie);
        if (receivedCookie.size() != COOKIE_SIZE) {
            LogDebug("No match in cookie size");
            return SECURITY_SERVER_API_ERROR_BAD_RESPONSE;
        }

        memcpy(cookie, &receivedCookie[0], receivedCookie.size());
        return retval;
    });
}

SECURITY_SERVER_API
int security_server_get_cookie_pid(const char *cookie)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;
    int pid;
    int retval = SECURITY_SERVER_API_ERROR_UNKNOWN;

    LogDebug("security_server_get_cookie_pid() called");

    if (cookie == NULL)
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

    //preprae cookie to send
    std::vector<char> key(cookie, cookie + COOKIE_SIZE);

    return try_catch([&] {
        //put data into buffer
        Serialization::Serialize(send, (int)CookieCall::CHECK_PID);
        Serialization::Serialize(send, key);

        //send buffer to server
        retval = sendToServer(SERVICE_SOCKET_COOKIE_CHECK, send.Pop(), recv);
        if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_SERVER_API_SUCCESS)
            return retval;

        Deserialization::Deserialize(recv, pid);
        return pid;
    });
}

SECURITY_SERVER_API
char * security_server_get_smacklabel_cookie(const char *cookie)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;
    int retval = SECURITY_SERVER_API_ERROR_UNKNOWN;
    std::string label;

    LogDebug("security_server_get_smacklabel_cookie() called");

    if (cookie == NULL)
        return NULL;

    //preprae cookie to send
    std::vector<char> key(cookie, cookie + COOKIE_SIZE);

    try {
        //put data into buffer
        Serialization::Serialize(send, (int)CookieCall::CHECK_SMACKLABEL);
        Serialization::Serialize(send, key);

        //send buffer to server
        retval = sendToServer(SERVICE_SOCKET_COOKIE_CHECK, send.Pop(), recv);
        if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return NULL;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_SERVER_API_SUCCESS)
            return NULL;

        Deserialization::Deserialize(recv, label);

        return strdup(label.c_str());

    } catch (MessageBuffer::Exception::Base &e) {
        LogDebug("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogDebug("STD exception " << e.what());
    } catch (...) {
        LogDebug("Unknown exception occured");
    }

    return NULL;
}

SECURITY_SERVER_API
int security_server_check_privilege(const char *cookie, gid_t privilege)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;
    int retval = SECURITY_SERVER_API_ERROR_UNKNOWN;

    LogDebug("security_server_check_privilege() called");

    if (cookie == NULL)
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

    //preprae cookie to send
    std::vector<char> key(cookie, cookie + COOKIE_SIZE);

    return try_catch([&] {
        //put data into buffer
        Serialization::Serialize(send, (int)CookieCall::CHECK_PRIVILEGE_GID);
        Serialization::Serialize(send, key);
        Serialization::Serialize(send, (int)privilege);

        //send buffer to server
        retval = sendToServer(SERVICE_SOCKET_COOKIE_CHECK, send.Pop(), recv);
        if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        return retval;
    });
}

SECURITY_SERVER_API
int security_server_check_privilege_by_cookie(
    const char *cookie        SECURITY_SERVER_UNUSED,
    const char *object        SECURITY_SERVER_UNUSED,
    const char *access_rights SECURITY_SERVER_UNUSED)
{
#if 0
    using namespace SecurityServer;
    MessageBuffer send, recv;
    int retval = SECURITY_SERVER_API_ERROR_UNKNOWN;

    LogDebug("security_server_check_privilege_by_cookie() called");

    if ((cookie == NULL) || (object == NULL) || (access_rights == NULL))
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

    //preprae cookie to send
    std::vector<char> key(cookie, cookie + COOKIE_SIZE);

    std::string obj(object);
    std::string access(access_rights);

    return try_catch([&] {
        //put data into buffer
        Serialization::Serialize(send, (int)CookieCall::CHECK_PRIVILEGE);
        Serialization::Serialize(send, key);
        Serialization::Serialize(send, obj);
        Serialization::Serialize(send, access);

        //send buffer to server
        retval = sendToServer(SERVICE_SOCKET_COOKIE_CHECK, send.Pop(), recv);
        if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        return retval;
    });
#endif
	return SECURITY_SERVER_API_SUCCESS;
}

SECURITY_SERVER_API
int security_server_get_uid_by_cookie(const char *cookie, uid_t *uid)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;
    int retval = SECURITY_SERVER_API_ERROR_UNKNOWN;

    LogDebug("security_server_get_uid_by_cookie() called");

    if ((cookie == NULL) || (uid == NULL))
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;

    //preprae cookie to send
    std::vector<char> key(cookie, cookie + COOKIE_SIZE);

    return try_catch([&] {
        //put data into buffer
        Serialization::Serialize(send, (int)CookieCall::CHECK_UID);
        Serialization::Serialize(send, key);

        //send buffer to server
        retval = sendToServer(SERVICE_SOCKET_COOKIE_CHECK, send.Pop(), recv);
        if (retval != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval == SECURITY_SERVER_API_SUCCESS) {
            int tmp;
            Deserialization::Deserialize(recv, tmp);
            *uid = static_cast<uid_t>(tmp);
        }

        return retval;
    });
}

