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
 * @file        client-get-gid.cpp
 * @author      Jan Olszak (j.olszak@samsung.com)
 * @version     1.0
 * @brief       This file constains implementation of get GID function.
 */

#include <stdio.h>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <socket-buffer.h>
#include <client-common.h>
#include <protocols.h>

#include <security-server.h>
#include <security-server-common.h>

SECURITY_SERVER_API
int security_server_get_gid(const char *objectName) {
    using namespace SecurityServer;
    try {
        if (NULL == objectName){
            LogDebug("Objects name is NULL");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        int objectsNameLen = strlen(objectName);
        if (0 == objectsNameLen || objectsNameLen > SECURITY_SERVER_MAX_OBJ_NAME){
            LogDebug("Objects name is empty or too long");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        SocketBuffer send, recv;
        Serialization::Serialize(send, std::string(objectName));

        int retCode = sendToServer(
          SERVICE_SOCKET_GET_GID,
          send.Pop(),
          recv);

        if (retCode != SECURITY_SERVER_API_SUCCESS)
            return retCode;

        Deserialization::Deserialize(recv, retCode);

        // Return if errors
        if (retCode < 0)
            return retCode;

        // No errors, return gid
        gid_t gid;
        Deserialization::Deserialize(recv, gid);
        return gid;
    } catch (SocketBuffer::Exception::Base &e) {
        LogDebug("SecurityServer::SocketBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogDebug("STD exception " << e.what());
    } catch (...) {
        LogDebug("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

