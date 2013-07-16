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
 * @file        exec-path.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of api-exec-path service.
 */

#include <string>

#include <unistd.h>
#include <sys/smack.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <protocols.h>
#include <exec-path.h>
#include <security-server.h>
#include <security-server-util.h>
#include <smack-check.h>

namespace {
// Service may open more than one socket.
// These ID's will be assigned to sockets
// and will be used only by service.
// When new connection arrives, AcceptEvent
// will be generated with proper ID to inform
// service about input socket.
//
// Please note: SocketManaged does not use it and
// does not check it in any way.
//
// If your service require only one socket
// (uses only one socket labeled with smack)
// you may ignore this ID (just pass 0)
const int SERVICE_SOCKET_ID = 0;

} // namespace anonymous

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector ExecPathService::GetServiceDescription() {
    ServiceDescription sd = {
        "security-server",
        SERVICE_SOCKET_ID,
        SERVICE_SOCKET_EXEC_PATH
    };
    ServiceDescriptionVector v;
    v.push_back(sd);
    return v;
}

void ExecPathService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
}

void ExecPathService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

bool ExecPathService::processOne(const ConnectionID &conn, SocketBuffer &buffer) {
    LogDebug("Processing message");

    int pid = 0;
    char *exe;

    if (!buffer.Ready()) {
        LogDebug("Got part of message. Service is waiting for the rest.");
        return false;
    }

    Try {
        SecurityServer::Deserialization des;
        des.Deserialize(buffer, pid);
     } Catch (SocketBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    SecurityServer::Serialization ser;
    SocketBuffer sendBuffer;
    int retVal;

    // get executable path
    exe = read_exe_path_from_proc(pid);
    // quickly getting rid of allocated memory
    // when read_exe_path_from_proc will rewritten this won't be required
    std::string exec_path(exe ? exe : "");
    free(exe);

    if (exec_path.empty())
    {
         LogError("Server: Failed to read executable path for pid " << pid);
         retVal = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
         ser.Serialize(sendBuffer, retVal);
         m_serviceManager->Write(conn, sendBuffer.Pop());
         return true;
    }

    retVal = SECURITY_SERVER_API_SUCCESS;
    ser.Serialize(sendBuffer, retVal);
    ser.Serialize(sendBuffer, exec_path);
    m_serviceManager->Write(conn, sendBuffer.Pop());
    return true;
}

void ExecPathService::read(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &buffer = m_socketBufferMap[event.connectionID.counter];
    buffer.Push(event.rawBuffer);

    LogDebug("Pushed to buffer ptr: " << (void*)&buffer);
    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, buffer));
}

void ExecPathService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_socketBufferMap.erase(event.connectionID.counter);
}

void ExecPathService::error(const ErrorEvent &event) {
    LogDebug("ErrorEvent. ConnectionID: " << event.connectionID.sock);
    m_serviceManager->Close(event.connectionID);
}

} // namespace SecurityServer

