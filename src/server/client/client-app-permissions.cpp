/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bartlomiej Grzelewski <b.grzelewski@samsung.com>
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
 * @brief       This file contains implementation of
 *              security_server_app_has_privilege function
 */


#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>

#include <privilege-control.h>
#include <security-server.h>

SECURITY_SERVER_API
int security_server_app_has_privilege(const char *app_label,
                                      app_type_t app_type,
                                      const char *privilege_name,
                                      int *result)
{
    using namespace SecurityServer;
    MessageBuffer send, recv;

    LogDebug("security_server_app_has_privilege() called");

    try {
        if ((NULL == app_label) || (strlen(app_label) == 0)) {
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

        LogDebug("app_label: " << app_label);
        LogDebug("app_type: " << static_cast<int>(app_type));
        LogDebug("privilege_name: " << privilege_name);

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(PrivilegeCheckHdrs::CHECK_GIVEN_APP));
        Serialization::Serialize(send, std::string(app_label));
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
