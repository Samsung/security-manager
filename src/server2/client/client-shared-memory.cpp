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
 * @file        client-shared-memory.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file constains implementation of shared memory api.
 */

#include <stdio.h>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>
#include <smack-check.h>

#include <security-server.h>
#include <security-server-common.h>

SECURITY_SERVER_API
int security_server_app_give_access(const char *customer_label, int customer_pid) {
    using namespace SecurityServer;
    try {
        if (1 != smack_check())
            return SECURITY_SERVER_API_SUCCESS;

        if (NULL == customer_label || 0 == strlen(customer_label))
        {
            LogDebug("customer_label is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        MessageBuffer send, recv;
        Serialization::Serialize(send, std::string(customer_label));
        Serialization::Serialize(send, customer_pid);

        int result = sendToServer(
          SERVICE_SOCKET_SHARED_MEMORY,
          send.Pop(),
          recv);

        if (result != SECURITY_SERVER_API_SUCCESS)
            return result;

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

