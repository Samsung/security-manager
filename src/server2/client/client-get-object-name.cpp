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
 * @file        client-get-object-name.cpp
 * @author      Jan Olszak (j.olszak@samsung.com)
 * @version     1.0
 * @brief       This file constains implementation of get NAME function.
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
int security_server_get_object_name(gid_t gid, char *pObjectName, size_t maxObjectSize)
 {
    using namespace SecurityServer;
    try {
        if (pObjectName == NULL){
            LogDebug("Objects name is NULL or empty");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        SocketBuffer send, recv;
        Serialization ser;
        ser.Serialize(send, gid);

        int result = sendToServer(
          SERVICE_SOCKET_GET_OBJECT_NAME,
          send.Pop(),
          recv);


        if (result != SECURITY_SERVER_API_SUCCESS)
            return result;

        Deserialization des;
        des.Deserialize(recv, result);

        std::string retObjectName;
        des.Deserialize(recv, retObjectName);

        if(retObjectName.size() > maxObjectSize){
            LogError("Objects name is too big. Need more space in pObjectName buffer.");
            return SECURITY_SERVER_API_ERROR_BUFFER_TOO_SMALL;
        }

        strcpy(pObjectName,retObjectName.c_str());

        return result;

    } catch (SocketBuffer::Exception::Base &e) {
        LogDebug("SecurityServer::SocketBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogDebug("STD exception " << e.what());
    } catch (...) {
        LogDebug("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

