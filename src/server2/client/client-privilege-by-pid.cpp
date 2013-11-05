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
 * @file        client-check-privilege-by-pid.cpp
 * @author      Jan Cybulski (j.cybulski@samsung.com)
 * @version     1.0
 * @brief       This file constains implementation of security-server API for
 * checking privilege by process id.
 */

#include <stdio.h>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>
#include <smack-check.h>
#include <signal.h>

#include <security-server.h>
#include <security-server-common.h>

SECURITY_SERVER_API
int security_server_check_privilege_by_pid(
        int pid,
        const char *object,
        const char *access_rights) {
    using namespace SecurityServer;
    return try_catch([&] {
        if (1 != smack_check())
            return SECURITY_SERVER_API_SUCCESS;

        // Checking whether a process with pid exists
        if ((pid < 0) || ((kill(pid, 0) == -1) && (errno == ESRCH))) {
            LogDebug("pid is invalid, process: " << pid << " does not exist");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (NULL == object || 0 == strlen(object)) {
            LogDebug("object param is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        if (NULL == access_rights || 0 == strlen(access_rights)) {
            LogDebug("access_right param is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        MessageBuffer send, recv;
        Serialization::Serialize(send, pid);
        Serialization::Serialize(send, std::string(object));
        Serialization::Serialize(send, std::string(access_rights));

        int result = sendToServer(
          SERVICE_SOCKET_PRIVILEGE_BY_PID,
          send.Pop(),
          recv);

        if (result != SECURITY_SERVER_API_SUCCESS)
            return result;

        Deserialization::Deserialize(recv, result);
        return result;
    });
}

