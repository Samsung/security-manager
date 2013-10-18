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
 * @file        client-app-permissions.cpp
 * @author      Pawel Polawski (pawel.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This file contain implementation of security_server_app_enable_permissions
 *              and security_server_app_disable functions
 */


#include <stdio.h>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>

#include <privilege-control.h>
#include <security-server.h>
#include <security-server-common.h>


SECURITY_SERVER_API
int security_server_app_enable_permissions(const char *app_id, app_type_t app_type, const char **perm_list, int persistent)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;
    std::vector<std::string> permissions_list;

    LogDebug("security_server_app_enable_permissions() called");

    try {
        if ((NULL == app_id) || (strlen(app_id) == 0)) {
            LogDebug("App_id is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if ((NULL == perm_list) || (strlen(perm_list[0]) == 0)) {
            LogDebug("Perm_list is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        LogDebug("app_type: " << (int)app_type);
        LogDebug("persistent: " << persistent);
        LogDebug("app_id: " << app_id);

        //put all strings in STL vector
        for (int i = 0; perm_list[i] != NULL; i++) {
            LogDebug("perm_list[" << i << "]: " << perm_list[i]);
            permissions_list.push_back(std::string(perm_list[i]));
        }

        //put data into buffer
        Serialization::Serialize(send, (int)AppPermissionsAction::ENABLE);   //works as a MSG_ID
        Serialization::Serialize(send, persistent);
        Serialization::Serialize(send, (int)app_type);
        Serialization::Serialize(send, std::string(app_id));
        Serialization::Serialize(send, permissions_list);

        //send buffer to server
        int result = sendToServer(SERVICE_SOCKET_APP_PERMISSIONS, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << result);
            return result;
        }

        //receive response from server
        Deserialization::Deserialize(recv, result);
        return result;

    } catch (MessageBuffer::Exception::Base &e) {
        LogDebug("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogDebug("STD exception " << e.what());
    } catch (...) {
        LogDebug("Unknown exception occured");
    }

    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}


SECURITY_SERVER_API
int security_server_app_disable_permissions(const char *app_id, app_type_t app_type, const char **perm_list)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;
    std::vector<std::string> permissions_list;

    LogDebug("security_server_app_disable_permissions() called");

    try {
        if ((NULL == app_id) || (strlen(app_id) == 0)) {
            LogDebug("App_id is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if ((NULL == perm_list) || (strlen(perm_list[0]) == 0)) {
            LogDebug("Perm_list is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        LogDebug("app_type: " << (int)app_type);
        LogDebug("app_id: " << app_id);

        //put all strings in STL vector
        for (int i = 0; perm_list[i] != NULL; i++) {
            LogDebug("perm_list[" << i << "]: " << perm_list[i]);
            permissions_list.push_back(std::string(perm_list[i]));
        }

        //put data into buffer
        Serialization::Serialize(send, (int)AppPermissionsAction::DISABLE);   //works as a MSG_ID
        Serialization::Serialize(send, (int)app_type);
        Serialization::Serialize(send, std::string(app_id));
        Serialization::Serialize(send, permissions_list);

        //send buffer to server
        int result = sendToServer(SERVICE_SOCKET_APP_PERMISSIONS, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << result);
            return result;
        }

        //receive response from server
        Deserialization::Deserialize(recv, result);
        return result;

    } catch (MessageBuffer::Exception::Base &e) {
        LogDebug("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogDebug("STD exception " << e.what());
    } catch (...) {
        LogDebug("Unknown exception occured");
    }

    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}


SECURITY_SERVER_API
int security_server_app_has_privilege(const char *app_id,
                                      app_type_t app_type,
                                      const char *privilege_name,
                                      int *result)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;

    LogDebug("security_server_app_has_privilege() called");

    try {
        if ((NULL == app_id) || (strlen(app_id) == 0)) {
            LogError("app_id is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if ((NULL == privilege_name) || (strlen(privilege_name) == 0)) {
            LogError("privilege_name is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (NULL == result) {
            LogError("result is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        LogDebug("app_id: " << app_id);
        LogDebug("app_type: " << static_cast<int>(app_type));
        LogDebug("privilege_name: " << privilege_name);

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(PrivilegeCheckCall::CHECK_GIVEN_APP));
        Serialization::Serialize(send, std::string(app_id));
        Serialization::Serialize(send, static_cast<int>(app_type));
        Serialization::Serialize(send, std::string(privilege_name));

        //send buffer to server
        int apiResult = sendToServer(SERVICE_SOCKET_APP_PRIVILEGE_BY_NAME, send.Pop(), recv);
        if (apiResult != SECURITY_SERVER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << apiResult);
            return apiResult;
        }

        //receive response from server
        Deserialization::Deserialize(recv, apiResult);
        if (apiResult == SECURITY_SERVER_API_SUCCESS) {
            Deserialization::Deserialize(recv, *result);
        }
        return apiResult;

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
int security_server_app_caller_has_privilege(app_type_t app_type,
                                             const char *privilege_name,
                                             int *result)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;

    LogDebug("security_server_app_caller_has_privilege() called");

    try {
        if ((NULL == privilege_name) || (strlen(privilege_name) == 0)) {
            LogError("privilege_name is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }
        if (NULL == result) {
            LogError("result is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        LogDebug("app_type: " << static_cast<int>(app_type));
        LogDebug("privilege_name: " << privilege_name);

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(PrivilegeCheckCall::CHECK_CALLER_APP));
        Serialization::Serialize(send, static_cast<int>(app_type));
        Serialization::Serialize(send, std::string(privilege_name));

        //send buffer to server
        int apiResult = sendToServer(SERVICE_SOCKET_APP_PRIVILEGE_BY_NAME, send.Pop(), recv);
        if (apiResult != SECURITY_SERVER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << apiResult);
            return apiResult;
        }

        //receive response from server
        Deserialization::Deserialize(recv, apiResult);
        if (apiResult == SECURITY_SERVER_API_SUCCESS) {
            Deserialization::Deserialize(recv, *result);
        }
        return apiResult;

    } catch (MessageBuffer::Exception::Base &e) {
        LogError("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }

    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}
